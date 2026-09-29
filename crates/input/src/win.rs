//! Windows `SendInput` backend.
//!
//! Every event becomes one (or, for a two-axis scroll, two) `INPUT` records
//! passed to `SendInput`. Mouse moves use absolute virtual-desktop coordinates;
//! the pixel→`0..=65535` mapping is the pure [`crate::axis_to_absolute`].

use anyhow::Context as _;
use cleandesk_proto::message::{InputEvent, MonitorInfo, MouseButton};
use windows::Win32::System::Shutdown::LockWorkStation;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    BlockInput, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, WHEEL_DELTA, XBUTTON1, XBUTTON2,
};

use crate::{mouse_move_absolute, InputInjector, VirtualScreen};

/// `InputInjector` implemented with the Windows `SendInput` API.
///
/// Events are handed to a dedicated OS thread: `SendInput` only reaches the
/// desktop the *calling thread* is attached to, and following the input
/// desktop (UAC prompts, lock screen) means calling `SetThreadDesktop`, which
/// must not happen on shared async worker threads. The thread re-checks the
/// input desktop every [`ATTACH_INTERVAL`] and after any failed injection.
pub struct WinInputInjector {
    tx: std::sync::mpsc::Sender<Job>,
}

struct Job {
    ev: InputEvent,
    monitor: MonitorInfo,
}

/// How often the injector thread looks for a desktop switch.
const ATTACH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

impl Default for WinInputInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl WinInputInjector {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let spawned = std::thread::Builder::new()
            .name("cleandesk-input".into())
            .spawn(move || injector_thread(rx));
        if let Err(e) = spawned {
            tracing::error!(error = %e, "could not spawn the input thread; input will be dropped");
        }
        Self { tx }
    }
}

fn injector_thread(rx: std::sync::mpsc::Receiver<Job>) {
    let mut last_attach = std::time::Instant::now() - ATTACH_INTERVAL;
    let mut force_attach = true;
    while let Ok(job) = rx.recv() {
        if force_attach || last_attach.elapsed() >= ATTACH_INTERVAL {
            last_attach = std::time::Instant::now();
            force_attach = false;
            match cleandesk_platform::desktop::attach_input_desktop() {
                Ok(true) => tracing::info!("input thread followed the input desktop"),
                Ok(false) => {}
                Err(e) => tracing::debug!(error = %e, "could not follow the input desktop"),
            }
        }
        if let Err(e) = inject_now(job.ev, &job.monitor) {
            tracing::warn!(error = %e, "input injection failed");
            force_attach = true;
        }
    }
    tracing::debug!("input thread stopped");
}

impl InputInjector for WinInputInjector {
    fn inject(&mut self, ev: InputEvent, monitor: &MonitorInfo) -> anyhow::Result<()> {
        self.tx
            .send(Job { ev, monitor: monitor.clone() })
            .map_err(|_| anyhow::anyhow!("input thread is gone"))
    }
}

/// Inject one event on the calling thread's desktop.
fn inject_now(ev: InputEvent, monitor: &MonitorInfo) -> anyhow::Result<()> {
        match ev {
            InputEvent::MouseMove { x, y } => {
                let vs = virtual_screen();
                let (dx, dy) = mouse_move_absolute(x, y, monitor, &vs);
                send(&[mouse_input(
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    0,
                    dx,
                    dy,
                )])
            }
            InputEvent::MouseButton { button, pressed } => {
                let (flags, data) = button_action(button, pressed);
                send(&[mouse_input(flags, data, 0, 0)])
            }
            InputEvent::MouseScroll { delta_x, delta_y } => {
                // Vertical first, then horizontal; skip zero axes.
                let mut inputs = Vec::with_capacity(2);
                if delta_y != 0.0 {
                    inputs.push(mouse_input(MOUSEEVENTF_WHEEL, wheel_amount(delta_y) as u32, 0, 0));
                }
                if delta_x != 0.0 {
                    inputs.push(mouse_input(MOUSEEVENTF_HWHEEL, wheel_amount(delta_x) as u32, 0, 0));
                }
                if inputs.is_empty() {
                    Ok(())
                } else {
                    send(&inputs)
                }
            }
            InputEvent::Key { code, pressed } => {
                let flags = if pressed {
                    KEYBD_EVENT_FLAGS(0)
                } else {
                    KEYEVENTF_KEYUP
                };
                send(&[key_input(code, flags)])
            }
        }
}

/// Read the virtual-desktop rectangle from the OS. Impure (the only Win32 query
/// in the mouse path); kept out of the coordinate math for testability.
fn virtual_screen() -> VirtualScreen {
    // SAFETY: GetSystemMetrics has no preconditions and returns 0 for an unknown
    // index; each SM_* here is a valid metric.
    unsafe {
        VirtualScreen {
            x: GetSystemMetrics(SM_XVIRTUALSCREEN),
            y: GetSystemMetrics(SM_YVIRTUALSCREEN),
            cx: GetSystemMetrics(SM_CXVIRTUALSCREEN),
            cy: GetSystemMetrics(SM_CYVIRTUALSCREEN),
        }
    }
}

/// Map a proto [`MouseButton`] + press state to the `SendInput` flag and the
/// `mouseData` value (nonzero only for the X buttons). Pure function.
fn button_action(button: MouseButton, pressed: bool) -> (MOUSE_EVENT_FLAGS, u32) {
    match button {
        MouseButton::Left => (
            if pressed { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP },
            0,
        ),
        MouseButton::Right => (
            if pressed { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP },
            0,
        ),
        MouseButton::Middle => (
            if pressed { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP },
            0,
        ),
        // "Back" is XBUTTON1, "Forward" is XBUTTON2; the button rides `mouseData`.
        MouseButton::Back => (
            if pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP },
            XBUTTON1 as u32,
        ),
        MouseButton::Forward => (
            if pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP },
            XBUTTON2 as u32,
        ),
    }
}

/// Convert a scroll delta in wheel notches to `mouseData` clicks
/// (`notches * WHEEL_DELTA`). Pure function.
fn wheel_amount(delta: f32) -> i32 {
    (delta * WHEEL_DELTA as f32).round() as i32
}

/// Build a mouse `INPUT`. `mouse_data` is reinterpreted as signed by the OS for
/// wheel events, so callers pass `value as u32`.
fn mouse_input(flags: MOUSE_EVENT_FLAGS, mouse_data: u32, dx: i32, dy: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Build a keyboard `INPUT` for a Windows VK `code`.
fn key_input(code: u32, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(code as u16),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Virtual-key codes for the secure-attention substitute.
const VK_SHIFT_CODE: u32 = 0x10;
const VK_CONTROL_CODE: u32 = 0x11;
const VK_ESCAPE_CODE: u32 = 0x1B;

/// See [`crate::lock_workstation`].
pub(crate) fn lock_workstation() -> anyhow::Result<()> {
    // SAFETY: LockWorkStation takes no arguments and has no preconditions.
    unsafe { LockWorkStation() }.context("LockWorkStation")
}

/// See [`crate::block_local_input`].
pub(crate) fn block_local_input(blocked: bool) -> anyhow::Result<()> {
    // SAFETY: BlockInput takes a plain BOOL and has no memory preconditions.
    unsafe { BlockInput(blocked) }.with_context(|| format!("BlockInput({blocked})"))
}

/// See [`crate::send_secure_attention`]: Ctrl+Shift+Esc, pressed and released
/// in one `SendInput` batch so a failure never leaves a modifier held.
pub(crate) fn send_secure_attention() -> anyhow::Result<()> {
    let down = KEYBD_EVENT_FLAGS(0);
    send(&[
        key_input(VK_CONTROL_CODE, down),
        key_input(VK_SHIFT_CODE, down),
        key_input(VK_ESCAPE_CODE, down),
        key_input(VK_ESCAPE_CODE, KEYEVENTF_KEYUP),
        key_input(VK_SHIFT_CODE, KEYEVENTF_KEYUP),
        key_input(VK_CONTROL_CODE, KEYEVENTF_KEYUP),
    ])
}

/// Submit a batch of `INPUT` records, failing if the OS inserted fewer than all
/// of them (e.g. blocked by UIPI / a higher-integrity foreground window).
fn send(inputs: &[INPUT]) -> anyhow::Result<()> {
    // SAFETY: `inputs` is a valid, non-aliased slice and `cbsize` is exactly
    // `size_of::<INPUT>()`, as SendInput requires.
    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if sent as usize != inputs.len() {
        let err = windows::core::Error::from_thread();
        return Err(anyhow::Error::new(err))
            .with_context(|| format!("SendInput inserted {sent}/{} events", inputs.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_flags_map_correctly() {
        assert_eq!(button_action(MouseButton::Left, true).0, MOUSEEVENTF_LEFTDOWN);
        assert_eq!(button_action(MouseButton::Left, false).0, MOUSEEVENTF_LEFTUP);
        assert_eq!(button_action(MouseButton::Right, true).0, MOUSEEVENTF_RIGHTDOWN);
        assert_eq!(button_action(MouseButton::Right, false).0, MOUSEEVENTF_RIGHTUP);
        assert_eq!(button_action(MouseButton::Middle, true).0, MOUSEEVENTF_MIDDLEDOWN);
        assert_eq!(button_action(MouseButton::Middle, false).0, MOUSEEVENTF_MIDDLEUP);
    }

    #[test]
    fn x_buttons_carry_mouse_data() {
        let (f, d) = button_action(MouseButton::Back, true);
        assert_eq!(f, MOUSEEVENTF_XDOWN);
        assert_eq!(d, XBUTTON1 as u32);
        let (f, d) = button_action(MouseButton::Forward, false);
        assert_eq!(f, MOUSEEVENTF_XUP);
        assert_eq!(d, XBUTTON2 as u32);
    }

    #[test]
    fn wheel_scales_by_wheel_delta() {
        assert_eq!(wheel_amount(1.0), WHEEL_DELTA as i32);
        assert_eq!(wheel_amount(-1.0), -(WHEEL_DELTA as i32));
        assert_eq!(wheel_amount(0.5), (WHEEL_DELTA / 2) as i32);
        assert_eq!(wheel_amount(0.0), 0);
    }

    #[test]
    fn negative_wheel_amount_reinterprets_as_u32() {
        // -120 as u32 is the two's-complement value the OS reads back as signed.
        assert_eq!(wheel_amount(-1.0) as u32, (-(WHEEL_DELTA as i32)) as u32);
    }
}
