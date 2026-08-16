//! Global (unfocused-window) push-to-talk, default Ctrl+Alt+P,
//! configurable via `~/.aloo/settings`. Reuses the same start/stop path
//! Space drives locally - this module only turns an OS-level key combo
//! into `Pressed`/`Released` events on a channel.
//!
//! Platform reality, verified against `global-hotkey` 0.8.0's own source:
//!
//! - **Windows**: `WM_HOTKEY` lands only on the message queue of the
//!   thread owning the crate's hidden window, and nothing in the crate
//!   pumps it - see `windows_pump::pump_forever`.
//! - **Linux**: X11 only; the crate's backend runs its own event thread,
//!   so `spawn` just keeps the `GlobalHotKeyManager` alive. Wayland has no
//!   equivalent at all - `is_wayland` lets the caller skip registration
//!   and warn once instead of silently failing later.
//! - **macOS**: Carbon `RegisterEventHotKey` (no Accessibility permission
//!   needed, unlike the crate's media-key path), but it requires the real
//!   main thread's `CFRunLoop` - see `main.rs` for how that's reconciled;
//!   this module spawns nothing itself on macOS.

use std::env;

use global_hotkey::hotkey::HotKey;
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// A press or release of the registered global push-to-talk shortcut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalPttEvent {
    Pressed,
    Released,
}

/// Whether this process is running under a Wayland session - the one
/// platform/display-server combination `global-hotkey` has no backend for
/// at all (its Linux support is X11-only; see module docs). Only ever
/// `true` on Linux; every other OS is unconditionally `false` here since
/// only Linux has more than one windowing system to distinguish between.
pub fn is_wayland() -> bool {
    cfg!(target_os = "linux")
        && is_wayland_session(
            env::var("XDG_SESSION_TYPE").ok().as_deref(),
            env::var_os("WAYLAND_DISPLAY").is_some(),
        )
}

/// Pure session-type check split out from `is_wayland` so it's testable
/// against synthetic values without mutating the real, global process
/// environment (unsafe to touch from parallel tests) - same reasoning as
/// `platform::resolve_home_dir`.
pub fn is_wayland_session(xdg_session_type: Option<&str>, wayland_display_set: bool) -> bool {
    xdg_session_type
        .map(|v| v.eq_ignore_ascii_case("wayland"))
        .unwrap_or(false)
        || wayland_display_set
}

/// Parses `configured` (as stored in `~/.aloo/settings`) into a `HotKey`,
/// falling back to the compiled-in default and printing a one-line warning
/// if it doesn't parse - a typo'd shortcut should never stop the app from
/// starting, just fall back to something that works.
pub fn resolve_hotkey(configured: &str) -> HotKey {
    match configured.parse::<HotKey>() {
        Ok(hotkey) => hotkey,
        Err(e) => {
            eprintln!(
                "aloo: global push-to-talk shortcut {configured:?} in ~/.aloo/settings is invalid ({e}); using the default {} instead",
                crate::settings::DEFAULT_GLOBAL_PTT_SHORTCUT
            );
            crate::settings::DEFAULT_GLOBAL_PTT_SHORTCUT
                .parse::<HotKey>()
                .expect("DEFAULT_GLOBAL_PTT_SHORTCUT is a valid HotKey string")
        }
    }
}

/// The hotkey to register, or `None` if registration should be skipped -
/// the user turned it off, or (Linux) the session runs under Wayland,
/// which `global_hotkey` has no backend for. The Wayland case warns once
/// at startup: don't retry, don't crash - Space still works while the app
/// is focused.
pub fn hotkey_to_register(settings: &crate::settings::Settings) -> Option<HotKey> {
    if !settings.global_ptt_enabled {
        return None;
    }
    if is_wayland() {
        eprintln!(
            "aloo: global push-to-talk ({}) needs X11 and isn't available under Wayland - Space still works while aloo is focused",
            settings.global_ptt_shortcut
        );
        return None;
    }
    Some(resolve_hotkey(&settings.global_ptt_shortcut))
}

/// Installs the process-wide handler that turns every `GlobalHotKeyEvent`
/// into a `GlobalPttEvent` on `tx`. This app only ever registers one
/// hotkey, so events aren't filtered by id. Must only be called once per
/// process - `GlobalHotKeyEvent::set_event_handler` silently keeps the
/// first handler it's given.
fn forward_events(tx: UnboundedSender<GlobalPttEvent>) {
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        let mapped = match event.state {
            HotKeyState::Pressed => GlobalPttEvent::Pressed,
            HotKeyState::Released => GlobalPttEvent::Released,
        };
        let _ = tx.send(mapped);
    }));
}

/// Registers `hotkey` and hands back the channel it delivers
/// `Pressed`/`Released` on, spawning one background thread that owns the
/// `GlobalHotKeyManager` for the process's life. `None` if registration
/// failed (combo already grabbed) - treated like the feature being
/// disabled. Not used on macOS, where the manager must live on the real
/// main thread (`register_on_current_thread`).
#[cfg(not(target_os = "macos"))]
pub fn spawn(hotkey: HotKey) -> Option<UnboundedReceiver<GlobalPttEvent>> {
    let (tx, rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();

    std::thread::spawn(move || {
        let manager = match GlobalHotKeyManager::new() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("aloo: could not initialize the global push-to-talk shortcut: {e}");
                let _ = ready_tx.send(false);
                return;
            }
        };
        forward_events(tx);
        if let Err(e) = manager.register(hotkey) {
            eprintln!("aloo: could not register the global push-to-talk shortcut ({hotkey}): {e}");
            let _ = ready_tx.send(false);
            return;
        }
        let _ = ready_tx.send(true);

        // Blocks for the rest of the process's life, keeping `manager`
        // alive (its `Drop` unregisters the hotkey) - see platform notes
        // in the module doc for what each branch is actually waiting on.
        #[cfg(target_os = "windows")]
        windows_pump::pump_forever();
        #[cfg(not(target_os = "windows"))]
        loop {
            std::thread::park();
        }
    });

    if ready_rx.recv().unwrap_or(false) {
        Some(rx)
    } else {
        None
    }
}

/// macOS only: registers `hotkey` on the calling thread, which must be the
/// process's real main thread (Carbon event delivery rides its
/// `CFRunLoop` - see module docs and `main.rs`). Returns the manager
/// (dropping it unregisters the hotkey, so the caller must keep it alive
/// for as long as the shortcut should keep working) and the event channel,
/// or `None` if registration failed.
#[cfg(target_os = "macos")]
pub fn register_on_current_thread(
    hotkey: HotKey,
) -> Option<(GlobalHotKeyManager, UnboundedReceiver<GlobalPttEvent>)> {
    let (tx, rx) = mpsc::unbounded_channel();
    let manager = match GlobalHotKeyManager::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("aloo: could not initialize the global push-to-talk shortcut: {e}");
            return None;
        }
    };
    forward_events(tx);
    if let Err(e) = manager.register(hotkey) {
        eprintln!("aloo: could not register the global push-to-talk shortcut ({hotkey}): {e}");
        return None;
    }
    Some((manager, rx))
}

/// macOS only: pumps the main thread's `CFRunLoop` in short slices until
/// `shutdown` is set, so Carbon can actually deliver the hotkey events
/// `register_on_current_thread` subscribed to. Must run on the process's
/// real main thread. 100ms slices keep shutdown latency low without busy
/// spinning.
#[cfg(target_os = "macos")]
pub fn pump_main_thread(shutdown: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    while !shutdown.load(Ordering::Relaxed) {
        macos_cf::run_main_run_loop_briefly(0.1);
    }
}

#[cfg(target_os = "windows")]
mod windows_pump {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, MSG, TranslateMessage,
    };

    /// Runs a standard Win32 message pump forever on the calling thread.
    /// See the module doc: `WM_HOTKEY` only reaches this thread's queue if
    /// something actually dispatches it.
    pub fn pump_forever() {
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let got = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if got <= 0 {
                // 0 = WM_QUIT, -1 = error; either way there's nothing left
                // to pump. This hidden window is never sent WM_QUIT in
                // normal operation, so in practice this loop runs for the
                // life of the process.
                break;
            }
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

/// Minimal hand-written Core Foundation bindings for the one function
/// `pump_main_thread` needs - not worth a whole `core-foundation` crate
/// dependency for a single FFI call, same call-the-framework-directly style
/// `global-hotkey`'s own macOS backend uses internally for the same
/// framework.
#[cfg(target_os = "macos")]
mod macos_cf {
    use std::ffi::c_void;

    type CFRunLoopRef = *mut c_void;
    type CFStringRef = *const c_void;
    type CFTimeInterval = f64;
    type Boolean = u8;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRunLoopGetMain() -> CFRunLoopRef;
        fn CFRunLoopRunInMode(
            mode: CFStringRef,
            seconds: CFTimeInterval,
            return_after_source_handled: Boolean,
        ) -> i32;
        static kCFRunLoopDefaultMode: CFStringRef;
    }

    /// Runs the main thread's `CFRunLoop` for up to `seconds`, returning
    /// early once it's handled a source (a fired hotkey callback, say) -
    /// same pattern Cocoa apps' own run loop already relies on, just
    /// pumped manually here since this app has no `NSApplication` event
    /// loop of its own.
    pub fn run_main_run_loop_briefly(seconds: f64) {
        unsafe {
            // Calling `CFRunLoopGetMain` also has the side effect of
            // ensuring the main run loop exists before anything tries to
            // add a source to it (`GlobalHotKeyManager::new` on this same
            // thread, called just before pumping starts).
            let _ = CFRunLoopGetMain();
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, 1);
        }
    }
}
