//! The durable shared-transfer history (US-066): what a record is, how a
//! file of them round-trips, and the rules the global transfers popup
//! rests on - live rows first, only finished ones removable, and a
//! transfer that was running when the process ended coming back as
//! interrupted rather than as still going.

use std::path::PathBuf;

use aloo::client::transfer_log::{
    MAX_RECORDS, TransferDirection, TransferLog, TransferRecord, TransferStatus, now_unix,
};

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-transfer-log-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn record(direction: TransferDirection, id: u64, peer: &str, status: TransferStatus) -> TransferRecord {
    TransferRecord {
        request_id: id,
        direction,
        peer_name: peer.to_string(),
        share: "Photos".into(),
        rel_path: "holiday".into(),
        status,
        files_total: Some(4),
        bytes_total: Some(4_000),
        files_done: 1,
        bytes_done: 1_000,
        files_skipped: 0,
        started_unix: now_unix(),
    }
}

/// @requirement AC-466
#[test]
fn a_history_round_trips_through_save_and_load() {
    let dir = scratch("round-trip");
    let path = dir.join("transfers");
    let mut log = TransferLog::new_empty(path.clone());
    log.start(record(TransferDirection::Download, 1, "alice", TransferStatus::Completed));
    log.start(record(TransferDirection::Upload, 2, "bob", TransferStatus::Cancelled));
    log.start(record(
        TransferDirection::Upload,
        3,
        "carol",
        TransferStatus::Failed("the link went away".into()),
    ));
    log.save().unwrap();

    let loaded = TransferLog::load(path);
    assert_eq!(loaded.records().len(), 3);
    let down = loaded.get(TransferDirection::Download, 1).expect("the download");
    assert_eq!(down.peer_name, "alice");
    assert_eq!(down.status, TransferStatus::Completed);
    assert_eq!(down.label(), "Photos/holiday");
    assert_eq!(down.bytes_total, Some(4_000));
    assert_eq!(
        loaded.get(TransferDirection::Upload, 3).unwrap().status,
        TransferStatus::Failed("the link went away".into()),
        "the reason survives with the record"
    );
    // The two directions are separate records even under one id.
    assert!(loaded.get(TransferDirection::Upload, 1).is_none());
    std::fs::remove_dir_all(&dir).ok();
}

/// Nothing resumes on its own across a restart, so a transfer that was
/// running when the process ended is history, not something still going.
/// @requirement AC-466
#[test]
fn a_transfer_running_at_shutdown_loads_as_interrupted() {
    let dir = scratch("interrupted");
    let path = dir.join("transfers");
    let mut log = TransferLog::new_empty(path.clone());
    log.start(record(TransferDirection::Download, 1, "alice", TransferStatus::Running));
    log.start(record(TransferDirection::Upload, 2, "bob", TransferStatus::Asking));
    log.start(record(TransferDirection::Download, 3, "carol", TransferStatus::Completed));
    log.save().unwrap();

    let loaded = TransferLog::load(path);
    assert_eq!(loaded.active(), 0, "nothing loads as still going");
    for (direction, id) in [(TransferDirection::Download, 1), (TransferDirection::Upload, 2)] {
        match &loaded.get(direction, id).unwrap().status {
            TransferStatus::Failed(why) => assert!(why.contains("restart"), "{why}"),
            other => panic!("expected an interrupted record, got {other:?}"),
        }
    }
    assert_eq!(
        loaded.get(TransferDirection::Download, 3).unwrap().status,
        TransferStatus::Completed,
        "one that had finished is untouched"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-467
#[test]
fn live_rows_come_first_then_the_most_recent() {
    let mut log = TransferLog::new_empty(PathBuf::from("unused"));
    let mut old_done = record(TransferDirection::Download, 1, "alice", TransferStatus::Completed);
    old_done.started_unix = 100;
    let mut new_done = record(TransferDirection::Upload, 2, "bob", TransferStatus::Completed);
    new_done.started_unix = 200;
    let mut running = record(TransferDirection::Download, 3, "carol", TransferStatus::Running);
    running.started_unix = 150;
    log.start(old_done);
    log.start(new_done);
    log.start(running);

    let ids: Vec<u64> = log.rows().iter().map(|r| r.request_id).collect();
    assert_eq!(
        ids,
        vec![3, 2, 1],
        "what is still moving first, then the most recent of the rest"
    );
}

/// @requirement AC-467
#[test]
fn only_finished_records_can_be_removed() {
    let mut log = TransferLog::new_empty(PathBuf::from("unused"));
    log.start(record(TransferDirection::Download, 1, "alice", TransferStatus::Running));
    log.start(record(TransferDirection::Upload, 2, "bob", TransferStatus::Completed));

    assert!(
        !log.clear(TransferDirection::Download, 1),
        "a running transfer is not forgotten while it is still moving"
    );
    assert_eq!(log.records().len(), 2);
    assert!(log.clear(TransferDirection::Upload, 2));
    assert_eq!(log.records().len(), 1);

    log.start(record(TransferDirection::Upload, 3, "bob", TransferStatus::Cancelled));
    log.start(record(TransferDirection::Download, 4, "dan", TransferStatus::Completed));
    assert_eq!(log.clear_finished(), 2);
    assert_eq!(log.records().len(), 1, "the running one is left");
    assert_eq!(log.active(), 1);
}

/// The file cannot grow without limit, and trimming never drops a
/// transfer that is still going.
/// @requirement AC-466
#[test]
fn the_history_is_capped_and_keeps_the_live_ones() {
    let mut log = TransferLog::new_empty(PathBuf::from("unused"));
    let mut running = record(TransferDirection::Download, 0, "alice", TransferStatus::Running);
    running.started_unix = 1;
    log.start(running);
    for i in 1..(MAX_RECORDS as u64 + 50) {
        let mut done = record(TransferDirection::Upload, i, "bob", TransferStatus::Completed);
        done.started_unix = 1_000 + i;
        log.start(done);
    }
    assert_eq!(log.records().len(), MAX_RECORDS);
    assert!(
        log.get(TransferDirection::Download, 0).is_some(),
        "the live one survives however much history piles up after it"
    );
}

/// A line this build does not fully understand still loads for what it
/// does - the same tolerance every other flat file here gives.
/// @requirement AC-466
#[test]
fn a_short_or_damaged_line_loads_for_what_it_carries() {
    let dir = scratch("tolerant");
    let path = dir.join("transfers");
    std::fs::write(
        &path,
        "7\tdown\talice\tPhotos\n\
         nonsense\n\
         \n\
         9\tsideways\tbob\tPhotos\tx\tdone\n\
         11\tup\tbob\tDocs\t\tdone\t2\t20\t2\t20\t0\t555\n",
    )
    .unwrap();

    let log = TransferLog::load(path);
    let ids: Vec<u64> = log.records().iter().map(|r| r.request_id).collect();
    assert_eq!(ids, vec![7, 11], "the unreadable ones are skipped, the rest load");
    let short = log.get(TransferDirection::Download, 7).unwrap();
    assert_eq!(short.share, "Photos");
    assert_eq!(short.files_done, 0, "a missing column reads as nothing");
    let full = log.get(TransferDirection::Upload, 11).unwrap();
    assert_eq!(full.bytes_done, 20);
    assert_eq!(full.started_unix, 555);
    std::fs::remove_dir_all(&dir).ok();
}

/// A tab or newline in a peer's own name cannot break the file it is
/// written into.
/// @requirement AC-466
#[test]
fn a_field_carrying_a_tab_cannot_break_the_line() {
    let dir = scratch("sanitize");
    let path = dir.join("transfers");
    let mut log = TransferLog::new_empty(path.clone());
    let mut awkward = record(TransferDirection::Download, 1, "alice", TransferStatus::Completed);
    awkward.share = "Ph\toto\ns".into();
    log.start(awkward);
    log.save().unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 1, "still one line: {text:?}");
    let loaded = TransferLog::load(path);
    assert_eq!(loaded.records().len(), 1);
    assert_eq!(loaded.records()[0].share, "Photos");
    std::fs::remove_dir_all(&dir).ok();
}
