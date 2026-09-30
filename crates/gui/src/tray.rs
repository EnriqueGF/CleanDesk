//! Icono en la bandeja del sistema.
//!
//! * Clic izquierdo / doble clic en el icono: muestra y trae al frente la
//!   ventana.
//! * Menú contextual: "Show RotoDesk" y "Quit".
//! * Con `Settings::minimize_to_tray` (por defecto activado), cerrar la
//!   ventana la oculta en vez de salir: el host sigue atendiendo conexiones.
//!   "Quit" del menú sí cierra la aplicación.
//!
//! `tray-icon` necesita un bucle de mensajes en el hilo que crea el icono; el
//! bucle de winit de eframe ya lo es, así que se construye dentro de
//! `RotoDeskApp::new`. Los eventos llegan por callbacks en otro hilo y se
//! reenvían por un canal, despertando a egui con `request_repaint`.

use std::sync::mpsc;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::i18n::tr;

/// Lo que la app debe hacer tras procesar los eventos de la bandeja.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    None,
    Show,
    Quit,
}

/// El icono vivo más sus canales de eventos.
pub struct Tray {
    _icon: TrayIcon,
    show_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
    rx: mpsc::Receiver<TrayMsg>,
}

enum TrayMsg {
    Icon(TrayIconEvent),
    Menu(MenuEvent),
}

impl Tray {
    /// Crea el icono. Falla (sin pánico) si el sistema no ofrece bandeja.
    /// `hwnd` es la ventana nativa: mientras está oculta egui no ejecuta
    /// `update`, así que mostrar/salir se hace desde el hilo de eventos.
    pub fn new(ctx: egui::Context, hwnd: Option<isize>) -> Result<Self, String> {
        let menu = Menu::new();
        let show = MenuItem::new(tr("Show RotoDesk"), true, None);
        let quit = MenuItem::new(tr("Quit"), true, None);
        menu.append(&show).map_err(|e| e.to_string())?;
        menu.append(&quit).map_err(|e| e.to_string())?;
        let show_id = show.id().clone();
        let quit_id = quit.id().clone();

        let (w, h, rgba) = icon_rgba(32);
        let icon = Icon::from_rgba(rgba, w, h).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel::<TrayMsg>();
        {
            let tx = tx.clone();
            let ctx = ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |ev: TrayIconEvent| {
                if matches!(
                    ev,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    }
                ) {
                    show_native_window(hwnd);
                }
                let _ = tx.send(TrayMsg::Icon(ev));
                ctx.request_repaint();
            }));
        }
        {
            let ctx = ctx.clone();
            let show_id = show_id.clone();
            let quit_id = quit_id.clone();
            MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
                if ev.id == quit_id {
                    // Con la ventana oculta el bucle de egui está parado y una
                    // petición de cierre nunca llegaría a procesarse. Los ajustes
                    // ya se guardan en cada cambio; salir aquí es seguro.
                    tracing::info!("quit from tray");
                    std::process::exit(0);
                }
                if ev.id == show_id {
                    show_native_window(hwnd);
                }
                let _ = tx.send(TrayMsg::Menu(ev));
                ctx.request_repaint();
            }));
        }

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("RotoDesk")
            .with_icon(icon)
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            _icon: icon,
            show_id,
            quit_id,
            rx,
        })
    }

    /// Drena los eventos pendientes y devuelve la acción de mayor prioridad.
    pub fn poll(&self) -> TrayAction {
        let mut action = TrayAction::None;
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                TrayMsg::Icon(TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                })
                | TrayMsg::Icon(TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }) => {
                    if action == TrayAction::None {
                        action = TrayAction::Show;
                    }
                }
                TrayMsg::Menu(ev) if ev.id == self.show_id => {
                    if action == TrayAction::None {
                        action = TrayAction::Show;
                    }
                }
                TrayMsg::Menu(ev) if ev.id == self.quit_id => action = TrayAction::Quit,
                _ => {}
            }
        }
        action
    }
}

/// Icono de la aplicación (`assets/icon-*.png`, generado por
/// `installer/make-icon.ps1`, la misma imagen que el `.ico` del instalador).
/// Devuelve (ancho, alto, RGBA) al tamaño pedido. Si el PNG embebido no se
/// pudiera decodificar (no debería ocurrir: es un recurso de compilación) se
/// devuelve un cuadrado verde para que la bandeja siga funcionando.
pub fn icon_rgba(size: u32) -> (u32, u32, Vec<u8>) {
    const SMALL: &[u8] = include_bytes!("../assets/icon-32.png");
    const LARGE: &[u8] = include_bytes!("../assets/icon-256.png");
    let bytes = if size <= 32 { SMALL } else { LARGE };
    match image::load_from_memory_with_format(bytes, image::ImageFormat::Png) {
        Ok(img) => {
            let img = if img.width() == size {
                img.into_rgba8()
            } else {
                img.resize_exact(size, size, image::imageops::FilterType::Lanczos3)
                    .into_rgba8()
            };
            (size, size, img.into_raw())
        }
        Err(e) => {
            tracing::warn!(error = %e, "embedded icon failed to decode");
            let mut rgba = vec![0u8; (size * size * 4) as usize];
            for px in rgba.chunks_exact_mut(4) {
                px.copy_from_slice(&[31, 138, 74, 255]);
            }
            (size, size, rgba)
        }
    }
}

/// Icono de ventana para eframe (misma imagen que la bandeja).
pub fn window_icon() -> egui::IconData {
    let (w, h, rgba) = icon_rgba(64);
    egui::IconData {
        rgba,
        width: w,
        height: h,
    }
}

/// La ventana nativa (HWND) de la app, si eframe la expone.
pub fn native_handle(cc: &eframe::CreationContext<'_>) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match cc.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

/// Muestra, restaura y trae al frente la ventana nativa. Funciona aunque el
/// bucle de egui esté parado (ventana oculta en la bandeja).
#[cfg(windows)]
pub fn show_native_window(hwnd: Option<isize>) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };
    // Si eframe no expuso el handle, buscamos nuestra ventana por título.
    let hwnd = match hwnd {
        Some(h) => HWND(h as *mut core::ffi::c_void),
        None => {
            let title: Vec<u16> = "RotoDesk\0".encode_utf16().collect();
            // SAFETY: valid NUL-terminated wide string; a miss returns an error.
            match unsafe { FindWindowW(None, windows::core::PCWSTR(title.as_ptr())) } {
                Ok(h) if !h.is_invalid() => h,
                _ => {
                    tracing::warn!("no native window handle to show");
                    return;
                }
            }
        }
    };
    tracing::info!(?hwnd, "showing native window");
    // SAFETY: plain Win32 calls on a window handle owned by this process; an
    // invalid handle makes them fail harmlessly.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }
        let _ = SetForegroundWindow(hwnd);
    }
}

#[cfg(not(windows))]
pub fn show_native_window(_hwnd: Option<isize>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_is_opaque_in_the_middle_and_transparent_at_corners() {
        for size in [32u32, 64, 256] {
            let (w, h, rgba) = icon_rgba(size);
            assert_eq!((w, h), (size, size));
            assert_eq!(rgba.len(), (size * size * 4) as usize);
            // Esquina: transparente (cuadrado redondeado).
            assert_eq!(rgba[3], 0, "corner alpha at {size}");
            // Centro: opaco.
            let i = ((size / 2) * size + size / 2) as usize * 4;
            assert!(rgba[i + 3] >= 240, "brand must remain visible at {size}px");
        }
    }
}
