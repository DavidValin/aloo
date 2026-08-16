# Migration log

Quantified record of each implemented refactor work item, appended in the
order the items were carried out.

## Find duplicate functions — 2026-08-16

- Files touched: 12
- Files removed: 0
- Lines of code removed: 155 (119 added for the shared implementations and doc updates; net −36)
- Functions merged/moved: 12
  - `client/idstore.rs::hex_encode` → `crypto::hex_encode`
  - `client/own_next_keys.rs::hex_encode` → `crypto::hex_encode`
  - `client/idstore.rs::hex_decode` → `crypto::hex_decode`
  - `client/own_next_keys.rs::hex_decode` → `crypto::hex_decode`
  - `client/connect.rs::is_storable` → `validation::is_storable`
  - `client/idstore.rs::is_storable` → `validation::is_storable`
  - `client/own_next_keys.rs::is_storable` → `validation::is_storable`
  - `client/direct_message.rs::encrypt_for_recipient` (KeyMode-dispatch body) → `client/envelope.rs::encrypt_envelope_for`
  - `client/channel.rs::encrypt_for_each` (KeyMode-dispatch body) → `client/envelope.rs::encrypt_envelope_for`
  - `client/channel.rs::handle_send_file` (inline KeyMode dispatch) → `client/envelope.rs::encrypt_envelope_for`
  - `client/tui/ui.rs::render_identity_button` → `client/tui/ui.rs::render_popup_button`
  - `client/tui/file_send.rs::render_confirm_button` → `client/tui/ui.rs::render_popup_button`
- Tests run: 642/642 (486 unit/integration + 156 cucumber scenarios), all passing: yes

Three byte-identical utility groups (`hex_encode` ×3, `hex_decode` ×2,
`is_storable` ×3) were collapsed into single shared implementations in
`crypto` and `validation`; the RSA-vs-PQ-hybrid envelope-encryption dispatch,
previously repeated in three send paths, became one
`envelope::encrypt_envelope_for`; and two identical popup-button renderers
became one width-parameterized `ui::render_popup_button`. Every consolidated
function's body is the surviving copy verbatim (button width preserved per
call site: 16 identity/file-offer, 18 file-send), callers were rewired
without signature or behavior changes, and `docs/PROTOCOL.md`/`docs/SPEC.md`
references were updated to the new locations.

## Find functions in wrong locations — 2026-08-16

- Files touched: 4
- Files removed: 0
- Lines of code removed: 43 (equivalent lines re-added at the new location; net ≈ +10 from doc-comment rewording)
- Functions merged/moved: 1
  - `client/tui/ui_connect_popup.rs::render_file_browser` → `client/tui/ui.rs::render_file_browser`
- Tests run: 642/642 (486 unit/integration + 156 cucumber scenarios), all passing: yes

`render_file_browser` renders the generic `FileBrowserState` for two
unrelated consumers (the connect popup's key-file picker and `file_send`'s
browser) but lived inside one of them, forcing `file_send.rs` to import a
renderer from the connect-popup module. It moved verbatim (same signature,
same visibility) into `tui/ui.rs`, the shared TUI base that already holds
the cross-popup render helpers; both consumers' imports and the module-doc
pointer in `file_browser.rs` were updated (its doc's stale
`render_message_log` reference was corrected to `render_messages`). The
full-inventory sweep found no other misplaced functions - the borderline
cases and the reasons they stay put are listed in the work-item analysis
(session.rs event dispatchers, proto.rs `KeyMode` label methods,
connect.rs cache cluster - the latter revisited under the merge-files
item).

## Merge files — 2026-08-16

- Files touched: 9
- Files removed: 2 (`src/client/file_stream.rs`, `src/client/tui/input.rs`)
- Lines of code removed: 270 (the two files' entire contents; ~245 re-added
  verbatim into the merge targets — net ≈ −5 after deduplicating module
  docs and imports: `file_transfer.rs` 92→333, `terminal.rs` 47→71)
- Functions merged/moved: 5 (moved verbatim, no signature changes)
  - `client/file_stream.rs::spawn_send_file_worker` → `client/file_transfer.rs::spawn_send_file_worker`
  - `client/file_stream.rs::spawn_receive_file_worker` → `client/file_transfer.rs::spawn_receive_file_worker`
  - `client/file_stream.rs::forward_chunk` → `client/file_transfer.rs::forward_chunk`
  - `client/file_stream.rs::end_incoming_transfer` → `client/file_transfer.rs::end_incoming_transfer`
  - `client/tui/input.rs::spawn_input_thread` → `client/tui/terminal.rs::spawn_input_thread`
- Tests run: 642/642 (486 unit/integration + 156 cucumber scenarios), all passing: yes

`file_stream.rs` (workers + per-transfer bookkeeping) merged into
`file_transfer.rs` (offer payload, chunking and filename policy): one
"file transfer" domain, previously split in two, now one module whose name
matches the docs and the existing test targets - `OwnFileTarget`,
`ActiveFileTransfer`, `FileEvent` and the four functions moved verbatim,
the two module docs were combined, and the five importing files switched
`file_stream::` to `file_transfer::`. `tui/input.rs` (one function, one
caller) merged into `tui/terminal.rs`, making that the single crossterm
terminal-I/O module (setup, restore, input thread). No `Cargo.toml` or
other configuration changes; `docs/SPEC.md`'s file list and
function-line references were updated. Rejected merges and reasons are in
the work-item analysis (`keymode_policy`, `sysstats`/`netstats`,
`p2p_proto`→`proto`, `p2p_reliable`→`p2p`).

## Simplify code comments — 2026-08-16

- Files touched: 27 (26 in `src/` + `docs/SPEC.md` reference re-sync)
- Files removed: 0
- Lines of code removed: ~540 (all comment lines; functional code untouched
  — `src/` comment volume went from 3,887 to 3,331 lines across the whole
  refactor, the overwhelming majority in this item)
- Functions merged/moved: 0
- Tests run: 642/642 (486 unit/integration + 156 cucumber scenarios), all passing: yes

Every comment block across `src/` was reviewed (all ~120 blocks of 7+
lines, plus a mechanical scan of every backticked identifier in comments
against the current codebase). Three stale references were fixed
(`route_direct_message` in `server/mod.rs`, which no longer exists;
`server.rs` as a path in `voice_stream.rs`; `ui_connect_popup.rs`'s claim
that `pq_hybrid` requires manual keygen before connecting, superseded by
`ensure_bundle_at`); pure git-history narration was removed ("used to live
in main.rs's event loop", "the old 64 KiB chunks", "the old TCP-relayed
design"); and the medium-length rationale essays (10-45 lines) were
compressed to roughly half while preserving every non-obvious claim -
protocol/security reasoning (identity gating, key-rotation races, hybrid
crypto scheme), platform quirks (musl `dlopen`, terminal key-release
detection, ALSA device sharing), and tuning rationale (datagram budgets,
timeouts) all survive in condensed form. `Cargo.toml`/`.cargo` comments
were left untouched per the configuration freeze, and `docs/SPEC.md`'s
`file:line` references were re-synced to the shifted line numbers (each
verified to point at its named function).
