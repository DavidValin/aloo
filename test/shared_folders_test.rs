//! Shared folders (US-066), the parts that are pure functions over a real
//! filesystem: the settings line, who may see what, confining a
//! peer-supplied path to the share it names, listing and walking a
//! folder, where a download lands, the upload pacer's arithmetic, and
//! the six sealed payloads' encoding.
//!
//! The wire exchange itself is `shared_session_test.rs`; the popups are
//! `ui_shared_browser_test.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aloo::client::shared_folders::{
    self, MAX_SHARED_ENTRIES_PER_RESPONSE, PACER_BURST_BYTES, PacerState, SharePacer, SharedEntry,
    SharedError, SharedFileTag, SharedFolderSummary, SharedListRequest, SharedListResponse,
    collect_download, download_dest, find_visible_share, forbidden_roots, format_size,
    is_forbidden, list_directory, rate_from_settings, resolve_shared_path, share_root_problem,
    visible_share_names,
};
use aloo::settings::{ShareAccess, SharedFolder, Settings};

/// No other share overlaps the one under test - the ordinary case, and
/// what every test here uses except the overlap ones themselves.
const NO_OVERLAP: &[PathBuf] = &[];

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-shared-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn share_at(dir: &Path, access: ShareAccess) -> SharedFolder {
    SharedFolder {
        path: dir.display().to_string(),
        access,
    }
}

/// Loads settings from a temp file holding exactly `contents` - the same
/// route a real start takes, since `Settings::parse` is private.
fn settings_from(label: &str, contents: &str) -> Settings {
    let dir = scratch(label);
    let path = dir.join("settings");
    std::fs::write(&path, contents).unwrap();
    let settings = Settings::load_or_create(&path).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    settings
}

fn users(names: &[&str]) -> ShareAccess {
    ShareAccess::Users(names.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>())
}

// ---------------------------------------------------------------------
// The settings line
// ---------------------------------------------------------------------

/// @requirement AC-448
#[test]
fn a_share_line_parses_all_and_named_users_and_round_trips() {
    let all = SharedFolder::parse("~/Public,all").expect("parses");
    assert_eq!(all.path, "~/Public");
    assert_eq!(all.access, ShareAccess::All);
    assert_eq!(all.name(), "Public");
    assert_eq!(all.to_setting_value(), "~/Public,all");

    let named = SharedFolder::parse("/srv/photos , alice , bob").expect("parses");
    assert_eq!(named.path, "/srv/photos");
    assert_eq!(named.access, users(&["alice", "bob"]));
    assert_eq!(named.name(), "photos");
    // Written back in the sorted order the set holds, so a save/load is
    // lossless rather than merely equivalent.
    assert_eq!(named.to_setting_value(), "/srv/photos,alice,bob");
    assert_eq!(
        SharedFolder::parse(&named.to_setting_value()).unwrap(),
        named
    );
}

/// A trailing separator names the same folder - the peer must not see
/// `Photos` under one line and nothing under the other.
/// @requirement AC-448
#[test]
fn a_trailing_separator_does_not_change_the_folder_name() {
    assert_eq!(SharedFolder::parse("/srv/Photos/,all").unwrap().name(), "Photos");
}

/// @requirement AC-448
#[test]
fn a_malformed_share_line_is_refused_with_a_reason() {
    for line in [
        "",              // no path at all
        "~/Public",      // nobody named
        "/,all",         // no folder name to share under
        "~/Public,",     // an empty access list
        "~/Public,al ice", // not a nickname
    ] {
        assert!(
            SharedFolder::parse(line).is_err(),
            "{line:?} should not parse as a share"
        );
    }
}

/// `all` is a keyword, not a nickname: a line mixing it with names is a
/// mistake to point out rather than a set containing "all".
/// @requirement AC-448
#[test]
fn all_cannot_be_mixed_with_nicknames() {
    assert!(SharedFolder::parse("~/Public,alice,all").is_err());
}

/// @requirement AC-448
#[test]
fn two_shares_with_the_same_folder_name_load_only_the_first() {
    let settings = settings_from(
        "dup-names",
        "share=/srv/a/Photos,all\nshare=/srv/b/Photos,alice\nshare=/srv/Videos,all\n",
    );
    let names: Vec<String> = settings.shares.iter().map(SharedFolder::name).collect();
    assert_eq!(names, vec!["Photos".to_string(), "Videos".to_string()]);
    assert_eq!(settings.shares[0].path, "/srv/a/Photos");
    assert_eq!(settings.shares_invalid.len(), 1, "{:?}", settings.shares_invalid);
    assert!(
        settings.shares_invalid[0].1.contains("already shared"),
        "{:?}",
        settings.shares_invalid
    );
}

/// @requirement AC-448
#[test]
fn a_malformed_line_is_kept_verbatim_with_its_reason() {
    let settings = settings_from("bad-line", "share=~/Public\nshare=~/Photos,all\n");
    assert_eq!(settings.shares.len(), 1);
    assert_eq!(settings.shares_invalid[0].0, "~/Public");
    assert!(!settings.shares_invalid[0].1.is_empty());
}

/// @requirement AC-448, AC-449
#[test]
fn share_settings_round_trip_through_save_and_load() {
    let dir = scratch("settings-round-trip");
    let path = dir.join("settings");
    let mut settings = Settings::load_or_create(&path).unwrap();
    assert!(settings.shares.is_empty(), "nothing is shared out of the box");

    settings.shares = vec![
        SharedFolder::parse("~/Public,all").unwrap(),
        SharedFolder::parse("~/Photos,alice,bob").unwrap(),
    ];
    settings.file_sharing_link_speed_kbps = 8_000;
    settings.file_sharing_max_pct = 25;
    settings.save(&path).unwrap();

    let loaded = Settings::load_or_create(&path).unwrap();
    assert_eq!(loaded.shares, settings.shares);
    assert_eq!(loaded.file_sharing_link_speed_kbps, 8_000);
    assert_eq!(loaded.file_sharing_max_pct, 25);
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-449
#[test]
fn file_sharing_speed_keys_default_to_uncapped_and_round_trip() {
    let settings = Settings::default();
    assert_eq!(settings.file_sharing_link_speed_kbps, 0, "no cap until declared");
    assert_eq!(settings.file_sharing_max_pct, 50);

    // A percentage that is not one leaves the default alone, like every
    // other numeric key in this file.
    let bad = settings_from("bad-pct", "file_sharing_max_pct=0\nfile_sharing_link_speed_kbps=x\n");
    assert_eq!(bad.file_sharing_max_pct, 50);
    assert_eq!(bad.file_sharing_link_speed_kbps, 0);

    let good = settings_from(
        "good-pct",
        "file_sharing_max_pct=80\nfile_sharing_link_speed_kbps=1000\n",
    );
    assert_eq!(good.file_sharing_max_pct, 80);
    assert_eq!(good.file_sharing_link_speed_kbps, 1000);
}

// ---------------------------------------------------------------------
// Who may see what
// ---------------------------------------------------------------------

/// @requirement AC-450
#[test]
fn visible_share_names_are_filtered_per_nickname() {
    let shares = vec![
        SharedFolder::parse("/srv/Public,all").unwrap(),
        SharedFolder::parse("/srv/Photos,alice,bob").unwrap(),
        SharedFolder::parse("/srv/Taxes,alice").unwrap(),
    ];
    assert_eq!(
        visible_share_names(&shares, "alice"),
        vec!["Public".to_string(), "Photos".to_string(), "Taxes".to_string()]
    );
    assert_eq!(
        visible_share_names(&shares, "bob"),
        vec!["Public".to_string(), "Photos".to_string()]
    );
    assert_eq!(visible_share_names(&shares, "carol"), vec!["Public".to_string()]);
}

/// The two refusals are one answer on purpose: telling "not yours" from
/// "not there" apart would let any linked peer probe for the names of
/// folders they were never announced.
/// @requirement TB-300
#[test]
fn a_share_not_meant_for_the_requester_is_refused_on_every_request() {
    let shares = vec![SharedFolder::parse("/srv/Photos,alice").unwrap()];
    assert!(find_visible_share(&shares, "alice", "Photos").is_ok());
    assert_eq!(
        find_visible_share(&shares, "carol", "Photos").unwrap_err(),
        SharedError::NoSuchShare,
        "a folder that is not theirs answers exactly as a missing one does"
    );
    assert_eq!(
        find_visible_share(&shares, "alice", "Videos").unwrap_err(),
        SharedError::NoSuchShare
    );
}

// ---------------------------------------------------------------------
// Overlapping shares
// ---------------------------------------------------------------------

/// Two shares can nest, and the narrower one is obviously the stricter
/// statement - so the wider one must not hand over what the narrower one
/// was drawn around, whichever way it is reached.
/// @requirement AC-461
#[test]
fn a_nested_share_a_peer_may_not_see_is_hidden_inside_one_they_may() {
    let dir = scratch("overlap");
    let work = dir.join("work");
    write(&work.join("notes.txt"), "1");
    write(&work.join("payroll/salaries.csv"), "secret");
    let shares = vec![
        share_at(&work, ShareAccess::All),
        share_at(&work.join("payroll"), users(&["alice"])),
    ];

    // Alice may see both, so nothing is hidden from her.
    let hers = forbidden_roots(&shares, "alice");
    assert!(hers.is_empty());
    let (entries, _) = list_directory(&work, "", &hers).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["payroll", "notes.txt"]);

    // Bob may see only the wider one, so the narrower disappears from it.
    let his = forbidden_roots(&shares, "bob");
    assert_eq!(his.len(), 1);
    let (entries, _) = list_directory(&work, "", &his).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["notes.txt"], "the nested share is not even listed");

    // And naming it directly is refused, not merely unlisted - the rule
    // holds however the path is reached.
    assert_eq!(
        resolve_shared_path(&work, "payroll", &his).unwrap_err(),
        SharedError::NoSuchShare
    );
    assert_eq!(
        resolve_shared_path(&work, "payroll/salaries.csv", &his).unwrap_err(),
        SharedError::NoSuchShare
    );

    // A download of the wider share takes nothing from inside it either.
    let (files, _) = collect_download(&work, "", &his);
    let rels: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(rels, vec!["notes.txt"]);
    let (files, _) = collect_download(&work, "", &hers);
    assert_eq!(files.len(), 2, "alice, who may see both, still gets both");
    std::fs::remove_dir_all(&dir).ok();
}

/// The same folder shared twice with different lists is the same
/// question: the one that excludes this peer wins.
/// @requirement AC-461
#[test]
fn the_most_restrictive_of_two_lines_for_one_folder_applies() {
    let dir = scratch("overlap-same");
    let public = dir.join("public");
    write(&public.join("a.txt"), "1");
    let shares = vec![
        share_at(&public, ShareAccess::All),
        share_at(&public, users(&["alice"])),
    ];

    let his = forbidden_roots(&shares, "bob");
    assert_eq!(his.len(), 1, "the line bob is not on forbids the folder");
    assert!(
        is_forbidden(&public.canonicalize().unwrap(), &his),
        "so the folder is out of bounds for him, by either line"
    );
    assert!(forbidden_roots(&shares, "alice").is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// The partial name a download is written under is never the name the
/// finished file will have.
/// @requirement AC-462
#[test]
fn a_partial_download_is_never_written_under_the_real_name() {
    let dest = Path::new("/tmp/aloo-x/holiday/beach.jpg");
    let partial = shared_folders::partial_path(dest);
    assert_ne!(partial, dest);
    assert_eq!(partial.parent(), dest.parent(), "same directory, so the move is a rename");
    assert!(
        partial.to_string_lossy().ends_with(shared_folders::PARTIAL_SUFFIX),
        "{}",
        partial.display()
    );
}

/// Where a browsed download lands: its own place, apart from the files
/// people send with `/file`, one folder per person.
/// @requirement AC-460
#[test]
fn fileshare_downloads_have_their_own_directory_per_person() {
    let dir = shared_folders::fileshare_download_dir("alice");
    assert!(dir.ends_with("downloads/fileshare/alice"), "{}", dir.display());
    // A file someone sends with `/file` still lands in the plain
    // downloads directory, not in here.
    assert_ne!(dir, aloo::client::file_transfer::default_download_dir());
}

// ---------------------------------------------------------------------
// Path confinement
// ---------------------------------------------------------------------

/// @requirement TB-300
#[test]
fn a_relative_path_cannot_escape_the_share() {
    let dir = scratch("confinement");
    let root = dir.join("share");
    write(&root.join("inside.txt"), "in");
    write(&dir.join("outside.txt"), "out");
    std::fs::create_dir_all(root.join("sub")).unwrap();

    assert_eq!(resolve_shared_path(&root, "", NO_OVERLAP).unwrap(), root.canonicalize().unwrap());
    assert!(resolve_shared_path(&root, "inside.txt", NO_OVERLAP).is_ok());
    assert!(resolve_shared_path(&root, "sub", NO_OVERLAP).is_ok());

    for escape in ["..", "../outside.txt", "sub/../../outside.txt", "./inside.txt"] {
        assert_eq!(
            resolve_shared_path(&root, escape, NO_OVERLAP).unwrap_err(),
            SharedError::NotAllowed,
            "{escape:?} should be refused"
        );
    }
    // An absolute path is not a relative one: its leading separator makes
    // an empty first component, and the rest is looked up under the share,
    // where it is not found.
    assert_eq!(
        resolve_shared_path(&root, "/etc/passwd", NO_OVERLAP).unwrap_err(),
        SharedError::NotFound
    );
    assert_eq!(
        resolve_shared_path(&root, "nope.txt", NO_OVERLAP).unwrap_err(),
        SharedError::NotFound
    );
    // Longer than the cap: refused before the filesystem is asked.
    let long = "a".repeat(shared_folders::MAX_SHARE_REL_PATH_CHARS + 1);
    assert_eq!(resolve_shared_path(&root, &long, NO_OVERLAP).unwrap_err(), SharedError::NotFound);
    std::fs::remove_dir_all(&dir).ok();
}

/// A folder whose name is legal here but not on Windows is still served
/// here: listing and downloading have to agree, or a file would appear in
/// the browser and then be silently missing from the download. What keeps
/// it safe is the containment check, not the character list.
/// @requirement TB-300
#[cfg(unix)]
#[test]
fn a_name_windows_would_refuse_is_still_served_on_unix() {
    let dir = scratch("unix-names");
    let root = dir.join("share");
    write(&root.join("back\\slash.txt"), "1");
    write(&root.join("notes:draft.txt"), "22");

    for name in ["back\\slash.txt", "notes:draft.txt"] {
        assert!(
            resolve_shared_path(&root, name, NO_OVERLAP).is_ok(),
            "{name:?} is an ordinary filename here and must be fetchable"
        );
    }
    // And the listing agrees with the download: everything it names can
    // actually be collected.
    let (entries, _) = list_directory(&root, "", NO_OVERLAP).unwrap();
    assert_eq!(entries.len(), 2);
    let (files, error) = collect_download(&root, "", NO_OVERLAP);
    assert!(error.is_none());
    assert_eq!(
        files.len(),
        2,
        "a listed file must not be silently skipped by the walk"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A NUL byte is legal in no path on any of the three platforms.
/// @requirement TB-300
#[test]
fn a_nul_byte_is_refused_everywhere() {
    let dir = scratch("nul");
    let root = dir.join("share");
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(
        resolve_shared_path(&root, "bad\0name", NO_OVERLAP).unwrap_err(),
        SharedError::NotAllowed
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A share path is written the way this platform writes one: absolute,
/// or starting `~/` (expanded from HOME, or USERPROFILE on Windows).
/// Each spelling has to survive parsing and name the folder it means.
/// @requirement AC-448, AC-459
#[test]
fn each_platforms_absolute_path_spelling_is_accepted() {
    // `~/` is the one spelling that reads the same everywhere, and it is
    // expanded rather than taken literally.
    let home = SharedFolder::parse("~/Public,all").unwrap();
    assert_eq!(home.name(), "Public");
    assert!(home.root().is_absolute(), "~/ expands to an absolute path");
    assert!(share_root_problem(&home).is_none_or(|p| p.contains("cannot be read")),
        "the only thing that may be wrong with ~/Public is that it is not there");

    if cfg!(windows) {
        for line in [
            "C:\\Users\\me\\Public,all",
            "C:/Users/me/Public,all",
            "\\\\server\\share\\Public,all",
        ] {
            let folder = SharedFolder::parse(line).unwrap();
            assert_eq!(folder.name(), "Public", "{line}");
            assert!(folder.root().is_absolute(), "{line} should be absolute here");
        }
    } else {
        let folder = SharedFolder::parse("/srv/Public,all").unwrap();
        assert_eq!(folder.name(), "Public");
        assert!(folder.root().is_absolute());
    }
}

/// The announced name is the folder's own final component under this
/// machine's separator rules - `/` everywhere, `\` on Windows too - so a
/// Linux folder whose name ends in a backslash is not renamed by being
/// shared.
/// @requirement AC-448
#[test]
fn the_folder_name_follows_this_platforms_separators() {
    assert_eq!(SharedFolder::parse("/srv/Photos,all").unwrap().name(), "Photos");
    assert_eq!(SharedFolder::parse("/srv/Photos/,all").unwrap().name(), "Photos");
    // Windows spells the same folder either way, and reads both.
    if cfg!(windows) {
        assert_eq!(
            SharedFolder::parse("C:\\srv\\Photos,all").unwrap().name(),
            "Photos"
        );
    } else {
        // Here a trailing backslash is part of the name, not a separator.
        assert_eq!(
            SharedFolder::parse("/srv/odd\\,all").unwrap().name(),
            "odd\\"
        );
    }
}

/// A link is judged by where it actually points, not by where it sits:
/// followed while it lands inside the folder that authorised it, and
/// neither listed nor served when it lands anywhere else. Covers each
/// shape a link can take, since only the plain file case is obvious.
/// @requirement TB-300, AC-461
#[cfg(unix)]
#[test]
fn a_link_out_of_the_authorised_folder_is_neither_listed_nor_served() {
    use std::os::unix::fs::symlink;
    let dir = scratch("links");
    let root = dir.join("share");
    write(&root.join("real.txt"), "in");
    write(&root.join("inner/nested.txt"), "in too");
    write(&root.join("payroll/p.csv"), "restricted");
    write(&dir.join("outside.txt"), "out");
    write(&dir.join("outside_dir/secret.txt"), "out");

    symlink(dir.join("outside.txt"), root.join("file_link_out.txt")).unwrap();
    symlink(dir.join("outside_dir"), root.join("dir_link_out")).unwrap();
    symlink(root.join("real.txt"), root.join("link_within.txt")).unwrap();
    symlink(dir.join("never-existed.txt"), root.join("broken.txt")).unwrap();
    symlink(root.join("payroll"), root.join("link_to_payroll")).unwrap();

    // `payroll` is a share of its own that this requester is not on, so
    // it is out of bounds by the most-restrictive rule as well.
    let shares = vec![
        share_at(&root, ShareAccess::All),
        share_at(&root.join("payroll"), users(&["alice"])),
    ];
    let forbidden = forbidden_roots(&shares, "bob");

    // Nothing that leaves the folder is even mentioned.
    let (entries, _) = list_directory(&root, "", &forbidden).unwrap();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["inner", "link_within.txt", "real.txt"],
        "a link out, a directory link out, a broken link and a link into a folder          this requester may not see are all left out of the listing"
    );

    // And naming any of them directly is refused - the listing is not
    // the only thing enforcing this.
    for (path, expected) in [
        ("file_link_out.txt", SharedError::NotAllowed),
        ("dir_link_out", SharedError::NotAllowed),
        ("dir_link_out/secret.txt", SharedError::NotAllowed),
        ("broken.txt", SharedError::NotFound),
        ("link_to_payroll", SharedError::NoSuchShare),
        ("link_to_payroll/p.csv", SharedError::NoSuchShare),
    ] {
        assert_eq!(
            resolve_shared_path(&root, path, &forbidden).unwrap_err(),
            expected,
            "{path} should be refused"
        );
    }

    // A link that stays inside is an ordinary file and is served.
    assert!(resolve_shared_path(&root, "link_within.txt", &forbidden).is_ok());

    // A download of the whole share takes only what is genuinely in it.
    let (files, error) = collect_download(&root, "", &forbidden);
    assert!(error.is_none());
    let mut rels: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
    rels.sort();
    assert_eq!(
        rels,
        vec!["inner/nested.txt", "link_within.txt", "real.txt"],
        "the walk follows nothing out of the folder either"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A symlink is only followed while it stays inside the share - the case
/// component checks alone cannot catch.
/// @requirement TB-300
#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_share_is_refused() {
    let dir = scratch("symlink");
    let root = dir.join("share");
    std::fs::create_dir_all(&root).unwrap();
    write(&dir.join("secret.txt"), "not yours");
    std::os::unix::fs::symlink(dir.join("secret.txt"), root.join("link.txt")).unwrap();

    assert_eq!(
        resolve_shared_path(&root, "link.txt", NO_OVERLAP).unwrap_err(),
        SharedError::NotAllowed
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// A share that cannot be served
// ---------------------------------------------------------------------

/// The three spellings that look right and quietly are not - the ones
/// that turn into a bare "not found" on whoever tried to browse them.
/// @requirement AC-459
#[test]
fn a_share_that_cannot_be_served_says_why() {
    let dir = scratch("root-problem");
    let real = dir.join("Public");
    std::fs::create_dir_all(&real).unwrap();
    let file = dir.join("notes.txt");
    write(&file, "x");

    let problem = |line: &str| share_root_problem(&SharedFolder::parse(line).unwrap());

    assert!(
        problem(&format!("{},all", real.display())).is_none(),
        "a real folder is servable"
    );

    // Relative: resolved against wherever aloo was started.
    let relative = problem("Public,all").expect("a relative path is a problem");
    assert!(relative.contains("relative"), "{relative}");

    // A shell variable is never expanded by aloo, in either platform's
    // spelling.
    for spelling in ["$HOME/Public,all", "${HOME}/Public,all", "%USERPROFILE%/Public,all"] {
        let shell = problem(spelling).unwrap_or_else(|| panic!("{spelling} should be refused"));
        assert!(shell.contains("shell variable"), "{spelling}: {shell}");
    }

    // Simply not there.
    let missing = problem(&format!("{},all", dir.join("Missing").display()))
        .expect("a missing folder is a problem");
    assert!(missing.contains("cannot be read"), "{missing}");

    // There, but not a folder.
    let not_dir = problem(&format!("{},all", file.display())).expect("a file is a problem");
    assert!(not_dir.contains("not a folder"), "{not_dir}");

    std::fs::remove_dir_all(&dir).ok();
}

/// The owner's own folder being unreadable is a different answer from an
/// item inside a working share being gone - one is their configuration,
/// the other is an ordinary miss.
/// @requirement AC-459
#[test]
fn an_unreadable_share_root_is_told_apart_from_a_missing_item() {
    let dir = scratch("root-vs-item");
    let root = dir.join("share");
    write(&root.join("there.txt"), "1");

    assert_eq!(
        list_directory(&dir.join("no-such-share"), "", NO_OVERLAP).unwrap_err(),
        SharedError::ShareUnavailable,
        "the share itself is what is broken"
    );
    assert_eq!(
        resolve_shared_path(&root, "gone.txt", NO_OVERLAP).unwrap_err(),
        SharedError::NotFound,
        "the share is fine; that one item is not there"
    );
    assert!(
        SharedError::ShareUnavailable
            .describe()
            .contains("their machine"),
        "the requester is told whose problem it is"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------
// Listing and walking
// ---------------------------------------------------------------------

/// @requirement AC-451
#[test]
fn a_listing_lists_folders_first_then_files_with_times_and_sizes() {
    let dir = scratch("listing");
    let root = dir.join("share");
    write(&root.join("b.txt"), "12345");
    write(&root.join("a.txt"), "1");
    write(&root.join("zeta/inner.txt"), "x");
    std::fs::create_dir_all(root.join("alpha")).unwrap();

    let (entries, truncated) = list_directory(&root, "", NO_OVERLAP).unwrap();
    assert!(!truncated);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "zeta", "a.txt", "b.txt"]);
    assert!(entries[0].is_dir && entries[1].is_dir);
    assert!(!entries[2].is_dir);
    assert_eq!(entries[2].size, 1);
    assert_eq!(entries[3].size, 5);
    assert!(
        entries[3].modified_unix.is_some(),
        "a modification time is recorded by every filesystem this runs on"
    );

    // And one level down, addressed by its relative path.
    let (inner, _) = list_directory(&root, "zeta", NO_OVERLAP).unwrap();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].name, "inner.txt");
    std::fs::remove_dir_all(&dir).ok();
}

/// A folder too large to list whole is not passed off as a complete
/// download - the files past the cap are left behind, and the answer
/// says so.
/// @requirement TB-301
#[test]
fn a_download_of_a_folder_cut_at_the_listing_cap_says_so() {
    let dir = scratch("walk-cap");
    let root = dir.join("share");
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..MAX_SHARED_ENTRIES_PER_RESPONSE + 5 {
        write(&root.join(format!("f{i:04}.txt")), "x");
    }
    let (files, error) = collect_download(&root, "", NO_OVERLAP);
    assert_eq!(files.len(), MAX_SHARED_ENTRIES_PER_RESPONSE);
    assert_eq!(
        error,
        Some(SharedError::TooLarge),
        "the requester is told files were left behind, not that all of them came"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-301
#[test]
fn a_listing_is_cut_at_the_cap_and_says_so() {
    let dir = scratch("cap");
    let root = dir.join("share");
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..MAX_SHARED_ENTRIES_PER_RESPONSE + 5 {
        write(&root.join(format!("f{i:04}.txt")), "x");
    }
    let (entries, truncated) = list_directory(&root, "", NO_OVERLAP).unwrap();
    assert_eq!(entries.len(), MAX_SHARED_ENTRIES_PER_RESPONSE);
    assert!(truncated, "the cap cut entries, so the answer must say so");
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-452
#[test]
fn a_folder_download_collects_every_file_with_its_relative_path() {
    let dir = scratch("walk");
    let root = dir.join("share");
    write(&root.join("top.txt"), "1");
    write(&root.join("sub/one.txt"), "22");
    write(&root.join("sub/deeper/two.txt"), "333");

    let (files, error) = collect_download(&root, "", NO_OVERLAP);
    assert!(error.is_none());
    let mut rels: Vec<String> = files.iter().map(|f| f.rel_path.clone()).collect();
    rels.sort();
    assert_eq!(
        rels,
        vec![
            "sub/deeper/two.txt".to_string(),
            "sub/one.txt".to_string(),
            "top.txt".to_string(),
        ]
    );
    let two = files.iter().find(|f| f.rel_path == "sub/deeper/two.txt").unwrap();
    assert_eq!(two.size, 3);
    assert_eq!(two.path, root.join("sub/deeper/two.txt").canonicalize().unwrap());

    // A subfolder alone, with paths relative to the share (not to it).
    let (sub, _) = collect_download(&root, "sub", NO_OVERLAP);
    let mut rels: Vec<String> = sub.iter().map(|f| f.rel_path.clone()).collect();
    rels.sort();
    assert_eq!(rels, vec!["sub/deeper/two.txt".to_string(), "sub/one.txt".to_string()]);
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-453
#[test]
fn a_single_file_download_is_just_that_file() {
    let dir = scratch("one-file");
    let root = dir.join("share");
    write(&root.join("sub/one.txt"), "22");
    write(&root.join("sub/two.txt"), "22");

    let (files, error) = collect_download(&root, "sub/one.txt", NO_OVERLAP);
    assert!(error.is_none());
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].rel_path, "sub/one.txt");
    assert_eq!(files[0].size, 2);

    // And a path that is not there says so rather than sending nothing
    // quietly.
    let (none, error) = collect_download(&root, "sub/missing.txt", NO_OVERLAP);
    assert!(none.is_empty());
    assert_eq!(error, Some(SharedError::NotFound));
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-452
#[test]
fn a_download_lands_under_owner_share_and_relative_path() {
    let downloads = Path::new("/tmp/aloo-downloads");
    assert_eq!(
        download_dest(downloads, "alice", "Photos", "trip/beach.jpg"),
        downloads.join("alice").join("Photos").join("trip").join("beach.jpg")
    );
    // Nothing a peer sends can name a path outside `downloads`: every
    // component goes through `safe_filename`.
    let hostile = download_dest(downloads, "../../etc", "Photos", "../../../root/.ssh/id_rsa");
    assert!(
        hostile.starts_with(downloads),
        "a hostile owner/rel path must stay under downloads: {}",
        hostile.display()
    );
    assert!(!hostile.to_string_lossy().contains(".."));

    // A Linux or macOS owner can legally share a folder Windows could not
    // create, and a Windows requester still has to be able to save it:
    // every component goes through `safe_filename`, which neutralizes the
    // reserved device names and the illegal characters wherever this runs.
    let awkward = download_dest(downloads, "alice", "CON", "a<b>|c.txt");
    let shown = awkward.to_string_lossy();
    assert!(shown.contains("_CON"), "a reserved device name is prefixed: {shown}");
    for illegal in ['<', '>', '|'] {
        assert!(
            !shown.contains(illegal),
            "{illegal:?} would make this uncreatable on Windows: {shown}"
        );
    }
    assert!(awkward.starts_with(downloads));
}

/// @requirement AC-451
#[test]
fn format_size_picks_the_unit() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(512), "512 B");
    assert_eq!(format_size(1_500), "1.5 KB");
    assert_eq!(format_size(12_000_000), "12.0 MB");
    assert_eq!(format_size(1_500_000_000), "1.5 GB");
}

// ---------------------------------------------------------------------
// The pacer
// ---------------------------------------------------------------------

/// @requirement AC-449
#[test]
fn the_rate_follows_the_two_settings() {
    // 8000 kbit/s is 1 MB/s; half of it is 500 KB/s.
    assert_eq!(rate_from_settings(8_000, 50), 500_000);
    assert_eq!(rate_from_settings(8_000, 100), 1_000_000);
    // An undeclared speed is no cap at all, whatever the percentage.
    assert_eq!(rate_from_settings(0, 50), 0);
}

/// The bucket's arithmetic, pinned without waiting: a burst runs free,
/// then each chunk costs exactly the time the rate says.
/// @requirement AC-456
#[test]
fn the_pacer_holds_a_send_to_the_configured_rate() {
    let start = Instant::now();
    let mut state = PacerState {
        balance: PACER_BURST_BYTES as i64,
        last: start,
    };
    let rate = 1_000; // bytes per second
    // The burst is spent first, at no cost.
    let burst = SharePacer::debit(&mut state, rate, PACER_BURST_BYTES, start);
    assert_eq!(burst, Duration::ZERO);
    // The next 1000 bytes, asked for at the same instant, are a full
    // second of debt.
    let wait = SharePacer::debit(&mut state, rate, 1_000, start);
    assert_eq!(wait, Duration::from_secs(1));
    // Time actually passing pays it back down.
    let later = start + Duration::from_secs(1);
    let after = SharePacer::debit(&mut state, rate, 1_000, later);
    assert_eq!(after, Duration::from_secs(1));
}

/// @requirement AC-456
#[test]
fn a_zero_rate_never_waits() {
    let now = Instant::now();
    let mut state = PacerState {
        balance: 0,
        last: now,
    };
    assert_eq!(
        SharePacer::debit(&mut state, 0, 10_000_000, now),
        Duration::ZERO
    );
    // And a real pacer with no rate returns immediately, which is what an
    // ordinary /file send relies on.
    let pacer = SharePacer::new(0);
    let before = Instant::now();
    pacer.acquire(1_000_000);
    assert!(before.elapsed() < Duration::from_millis(50));
}

/// The balance never grows past the bucket, so an idle transfer cannot
/// bank an unbounded burst and then blow through the cap.
/// @requirement AC-456
#[test]
fn a_burst_is_allowed_up_to_the_bucket() {
    let start = Instant::now();
    let mut state = PacerState {
        balance: 0,
        last: start,
    };
    // An hour of idleness at 1000 B/s "earns" 3.6 MB, but the bucket caps
    // what can be banked.
    let much_later = start + Duration::from_secs(3600);
    SharePacer::debit(&mut state, 1_000, 0, much_later);
    assert_eq!(state.balance, PACER_BURST_BYTES as i64);
}

/// @requirement AC-449, AC-456
#[test]
fn a_rate_change_applies_to_a_running_pacer() {
    let pacer = SharePacer::new(1_000);
    assert_eq!(pacer.rate(), 1_000);
    pacer.set_rate(rate_from_settings(8_000, 50));
    assert_eq!(pacer.rate(), 500_000);
}

// ---------------------------------------------------------------------
// The payloads
// ---------------------------------------------------------------------

/// @requirement TB-299
#[test]
fn payloads_round_trip_through_proto_encode() {
    let list = vec![SharedFolderSummary { name: "Photos".into() }];
    let encoded = aloo::proto::encode(&list).unwrap();
    assert_eq!(
        aloo::proto::decode::<Vec<SharedFolderSummary>>(&encoded).unwrap(),
        list
    );

    let request = SharedListRequest {
        request_id: 7,
        share: "Photos".into(),
        rel_path: "trip/beach".into(),
    };
    let encoded = aloo::proto::encode(&request).unwrap();
    assert_eq!(
        aloo::proto::decode::<SharedListRequest>(&encoded).unwrap(),
        request
    );

    let response = SharedListResponse {
        request_id: 7,
        entries: vec![SharedEntry {
            name: "beach.jpg".into(),
            is_dir: false,
            size: 42,
            created_unix: Some(1_700_000_000),
            modified_unix: None,
        }],
        truncated: true,
        error: Some(SharedError::NotAllowed),
    };
    let encoded = aloo::proto::encode(&response).unwrap();
    assert_eq!(
        aloo::proto::decode::<SharedListResponse>(&encoded).unwrap(),
        response
    );

    let tag = SharedFileTag {
        request_id: 7,
        stream_id: 3,
        rel_path: "trip/beach.jpg".into(),
    };
    let encoded = aloo::proto::encode(&tag).unwrap();
    assert_eq!(aloo::proto::decode::<SharedFileTag>(&encoded).unwrap(), tag);
}

/// Every share's own root is what a listing reads, `~` expanded - the
/// path in the file is never used directly.
/// @requirement AC-448
#[test]
fn a_share_root_expands_a_leading_tilde() {
    let share = share_at(Path::new("/srv/Photos"), ShareAccess::All);
    assert_eq!(share.root(), PathBuf::from("/srv/Photos"));
    let home = SharedFolder::parse("~/Photos,all").unwrap();
    assert_ne!(home.root(), PathBuf::from("~/Photos"), "the tilde must be expanded");
    assert!(home.root().ends_with("Photos"));
}
