//! Reusable TUI widgets - the pieces more than one popup or view draws
//! identically, factored out so a shape is described once rather than
//! re-derived per call site.
//!
//! Distinct from `crate::client::tui::ui`, which owns the *connected
//! screen's* own state and rendering: nothing here knows about `UiState`,
//! a session, or any particular popup's meaning. A widget takes a `Rect`,
//! some values, and draws.

pub mod confirm_popup;
