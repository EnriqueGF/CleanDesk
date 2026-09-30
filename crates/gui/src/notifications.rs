//! CleanDesk's own desktop toasts. A separate native message loop keeps them
//! working while the main egui window is hidden, without stealing focus.
use cleandesk_proto::CleanDeskId;

#[derive(Clone)]
pub struct Notification {
    pub name: String,
    pub id: CleanDeskId,
    pub online: bool,
}

pub struct Notifications {
    sender: std::sync::mpsc::SyncSender<Notification>,
}

impl Notifications {
    pub fn new(hwnd: Option<isize>) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(8);
        if let Err(e) = std::thread::Builder::new()
            .name("cleandesk-notifications".into())
            .spawn(move || native::run(receiver, hwnd))
        {
            tracing::warn!(error = %e, "notification thread unavailable");
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("CLEANDESK_NOTIFICATION_PREVIEW").is_some() {
            let _ = sender.try_send(Notification {
                name: "PC de ejemplo".into(),
                id: CleanDeskId::new(123456789).unwrap(),
                online: true,
            });
            let _ = sender.try_send(Notification {
                name: "Portátil de ejemplo".into(),
                id: CleanDeskId::new(987654321).unwrap(),
                online: false,
            });
        }
        Self { sender }
    }
    pub fn send(&self, notification: Notification) {
        let _ = self.sender.try_send(notification);
    }
}

#[cfg(windows)]
mod native {
    use super::Notification;
    use std::sync::mpsc::{Receiver, TryRecvError};
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow};
    use windows::Win32::UI::WindowsAndMessaging::*;

    struct Toast {
        notification: Notification,
        main: Option<isize>,
        scale: f32,
    }
    fn px(value: i32, scale: f32) -> i32 {
        (value as f32 * scale).round() as i32
    }
    fn color(r: u8, g: u8, b: u8) -> COLORREF {
        COLORREF(r as u32 | ((g as u32) << 8) | ((b as u32) << 16))
    }

    // SAFETY: each HWND is owned and pumped by this thread. Toast userdata is
    // retained at WM_NCCREATE and released exactly once at WM_NCDESTROY.
    unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        unsafe {
            if msg == WM_NCCREATE {
                let create = &*(lp.0 as *const CREATESTRUCTW);
                std::sync::Arc::increment_strong_count(create.lpCreateParams as *const Toast);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
            }
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Toast;
            if !ptr.is_null() {
                let toast = &*ptr;
                match msg {
                    WM_PAINT => {
                        paint(hwnd, toast);
                        return LRESULT(0);
                    }
                    WM_PRINTCLIENT => {
                        draw(HDC(wp.0 as *mut _), toast);
                        return LRESULT(0);
                    }
                    WM_ERASEBKGND => return LRESULT(1),
                    WM_MOUSEACTIVATE => return LRESULT(MA_NOACTIVATE as isize),
                    WM_TIMER | WM_CLOSE => {
                        let _ = DestroyWindow(hwnd);
                        return LRESULT(0);
                    }
                    WM_LBUTTONUP => {
                        let x = (lp.0 & 0xffff) as i16 as i32;
                        if x < px(322, toast.scale) {
                            crate::tray::show_native_window(toast.main);
                        }
                        let _ = DestroyWindow(hwnd);
                        return LRESULT(0);
                    }
                    WM_NCDESTROY => {
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                        drop(std::sync::Arc::from_raw(ptr));
                    }
                    _ => {}
                }
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
    }

    unsafe fn text(
        hdc: HDC,
        value: &str,
        rect: RECT,
        size: i32,
        bold: bool,
        scale: f32,
        ink: COLORREF,
    ) {
        unsafe {
            let font = CreateFontW(
                -px(size, scale),
                0,
                0,
                0,
                if bold { 600 } else { 400 },
                0,
                0,
                0,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                DEFAULT_PITCH.0 as u32,
                w!("Segoe UI"),
            );
            let old = SelectObject(hdc, font.into());
            SetTextColor(hdc, ink);
            SetBkMode(hdc, TRANSPARENT);
            let mut value: Vec<u16> = value.encode_utf16().collect();
            let mut rect = rect;
            DrawTextW(
                hdc,
                &mut value,
                &mut rect,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX,
            );
            SelectObject(hdc, old);
            let _ = DeleteObject(font.into());
        }
    }

    unsafe fn paint(hwnd: HWND, toast: &Toast) {
        unsafe {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            draw(hdc, toast);
            let _ = EndPaint(hwnd, &ps);
        }
    }

    unsafe fn draw(hdc: HDC, toast: &Toast) {
        unsafe {
            let s = toast.scale;
            let rect = |x, y, w, h| RECT {
                left: px(x, s),
                top: px(y, s),
                right: px(x + w, s),
                bottom: px(y + h, s),
            };
            let background = CreateSolidBrush(color(247, 250, 248));
            FillRect(hdc, &rect(0, 0, 360, 124), background);
            let _ = DeleteObject(background.into());
            let accent = if toast.notification.online {
                color(23, 147, 91)
            } else {
                color(119, 131, 127)
            };
            let brush = CreateSolidBrush(accent);
            FillRect(hdc, &rect(0, 0, 5, 124), brush);
            let previous_brush = SelectObject(hdc, brush.into());
            let pen = CreatePen(PS_SOLID, 1, accent);
            let previous_pen = SelectObject(hdc, pen.into());
            let _ = Ellipse(hdc, px(22, s), px(49, s), px(48, s), px(75, s));
            SelectObject(hdc, previous_pen);
            SelectObject(hdc, previous_brush);
            let _ = DeleteObject(pen.into());
            let _ = DeleteObject(brush.into());
            text(
                hdc,
                "CleanDesk",
                rect(22, 12, 290, 23),
                13,
                true,
                s,
                color(87, 110, 100),
            );
            text(
                hdc,
                &toast.notification.name,
                rect(62, 40, 268, 27),
                17,
                true,
                s,
                color(23, 47, 35),
            );
            let status = if toast.notification.online {
                crate::i18n::tr("Has connected")
            } else {
                crate::i18n::tr("Has disconnected")
            };
            text(hdc, status, rect(62, 69, 260, 23), 14, false, s, accent);
            text(
                hdc,
                &toast.notification.id.to_string(),
                rect(62, 94, 260, 17),
                11,
                false,
                s,
                color(119, 131, 127),
            );
            // Draw the close control as lines, independent of installed fonts.
            let pen = CreatePen(PS_SOLID, px(2, s).max(1), color(119, 131, 127));
            let old = SelectObject(hdc, pen.into());
            let _ = MoveToEx(hdc, px(335, s), px(16, s), None);
            let _ = LineTo(hdc, px(344, s), px(25, s));
            let _ = MoveToEx(hdc, px(344, s), px(16, s), None);
            let _ = LineTo(hdc, px(335, s), px(25, s));
            SelectObject(hdc, old);
            let _ = DeleteObject(pen.into());
        }
    }

    pub fn run(receiver: Receiver<Notification>, main: Option<isize>) {
        // SAFETY: native resources and their message dispatch remain on this
        // dedicated thread; pointers passed into windows stay live until close.
        unsafe {
            let Ok(module) = GetModuleHandleW(None) else {
                return;
            };
            let class = w!("CleanDeskPresenceToast");
            let wc = WNDCLASSW {
                style: CS_DROPSHADOW,
                lpfnWndProc: Some(window_proc),
                hInstance: module.into(),
                lpszClassName: class,
                hCursor: LoadCursorW(None, IDC_HAND).unwrap_or_default(),
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return;
            }
            let dpi = main
                .map(|h| GetDpiForWindow(HWND(h as *mut _)))
                .filter(|d| *d > 0)
                .unwrap_or_else(|| GetDpiForSystem());
            let scale = dpi as f32 / 96.0;
            let mut windows: Vec<HWND> = Vec::new();
            let mut running = true;
            while running {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                windows.retain(|h| IsWindow(Some(*h)).as_bool());
                let monitor = MonitorFromWindow(
                    main.map(|h| HWND(h as *mut _)).unwrap_or_default(),
                    MONITOR_DEFAULTTONEAREST,
                );
                let mut info = MONITORINFO {
                    cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                    ..Default::default()
                };
                if !GetMonitorInfoW(monitor, &mut info).as_bool() {
                    break;
                }
                // Compact the stack after a card closes; respect the taskbar work area.
                let height = px(124, scale);
                let width = px(360, scale);
                let gap = px(12, scale);
                for (i, hwnd) in windows.iter().enumerate() {
                    let _ = SetWindowPos(
                        *hwnd,
                        Some(HWND_TOPMOST),
                        info.rcWork.right - width - gap,
                        info.rcWork.bottom - gap - height - (i as i32) * (height + gap),
                        width,
                        height,
                        SWP_NOACTIVATE,
                    );
                }
                if windows.len() < 3 {
                    match receiver.try_recv() {
                        Ok(notification) => {
                            let toast = std::sync::Arc::new(Toast {
                                notification,
                                main,
                                scale,
                            });
                            let hwnd = CreateWindowExW(
                                WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                                class,
                                PCWSTR::null(),
                                WS_POPUP,
                                info.rcWork.right - width - gap,
                                info.rcWork.bottom
                                    - gap
                                    - height
                                    - (windows.len() as i32) * (height + gap),
                                width,
                                height,
                                None,
                                None,
                                Some(module.into()),
                                Some(std::sync::Arc::as_ptr(&toast).cast()),
                            );
                            match hwnd {
                                Ok(hwnd) => {
                                    let region = CreateRoundRectRgn(
                                        0,
                                        0,
                                        width + 1,
                                        height + 1,
                                        px(18, scale),
                                        px(18, scale),
                                    );
                                    if SetWindowRgn(hwnd, Some(region), true) == 0 {
                                        let _ = DeleteObject(region.into());
                                    }
                                    let _ = SetTimer(Some(hwnd), 1, 7000, None);
                                    let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                                    #[cfg(debug_assertions)]
                                    capture_preview(hwnd, toast.notification.online, width, height);
                                    windows.push(hwnd);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "could not create presence toast");
                                }
                            }
                        }
                        Err(TryRecvError::Disconnected) => running = false,
                        Err(TryRecvError::Empty) => {}
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            for hwnd in windows {
                let _ = DestroyWindow(hwnd);
            }
            let _ = UnregisterClassW(class, Some(module.into()));
        }
    }

    /// Debug-only captures of this popup's own paint output; no desktop pixels.
    #[cfg(debug_assertions)]
    unsafe fn capture_preview(hwnd: HWND, online: bool, width: i32, height: i32) {
        let Some(folder) = std::env::var_os("CLEANDESK_NOTIFICATION_PREVIEW") else {
            return;
        };
        unsafe {
            let dc = GetDC(Some(hwnd));
            let memory = CreateCompatibleDC(Some(dc));
            let bitmap = CreateCompatibleBitmap(dc, width, height);
            let old = SelectObject(memory, bitmap.into());
            SendMessageW(
                hwnd,
                WM_PRINTCLIENT,
                Some(WPARAM(memory.0 as usize)),
                Some(LPARAM(0)),
            );
            SelectObject(memory, old);
            let mut info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    biHeight: -height,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut rgba = vec![0u8; (width * height * 4) as usize];
            if GetDIBits(
                dc,
                bitmap,
                0,
                height as u32,
                Some(rgba.as_mut_ptr().cast()),
                &mut info,
                DIB_RGB_COLORS,
            ) > 0
            {
                for pixel in rgba.chunks_exact_mut(4) {
                    pixel.swap(0, 2);
                    pixel[3] = 255;
                }
                let path = std::path::PathBuf::from(folder).join(if online {
                    "notification-online.png"
                } else {
                    "notification-offline.png"
                });
                if let Err(e) = image::save_buffer(
                    path,
                    &rgba,
                    width as u32,
                    height as u32,
                    image::ColorType::Rgba8,
                ) {
                    tracing::warn!(error = %e, "toast preview failed");
                }
            }
            let _ = DeleteObject(bitmap.into());
            let _ = DeleteDC(memory);
            ReleaseDC(Some(hwnd), dc);
        }
    }
}

#[cfg(not(windows))]
mod native {
    pub fn run(receiver: std::sync::mpsc::Receiver<super::Notification>, _: Option<isize>) {
        while let Ok(notification) = receiver.recv() {
            tracing::info!(id = %notification.id, name = %notification.name, online = notification.online, "device presence changed");
        }
    }
}
