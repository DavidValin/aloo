//! The blocking terminal-input reader for the connected session:
//! `crossterm::event::read()` can't be awaited, so a dedicated OS thread
//! forwards every event onto a tokio channel that
//! `session::run_connected_session`'s select loop can consume. The thread
//! exits on its own once the receiver is dropped (send fails) or the
//! terminal goes away (read fails).

use crossterm::event::Event;
use tokio::sync::mpsc::UnboundedReceiver;

pub fn spawn_input_thread() -> UnboundedReceiver<Event> {
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        loop {
            match crossterm::event::read() {
                Ok(ev) => {
                    if input_tx.send(ev).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    input_rx
}
