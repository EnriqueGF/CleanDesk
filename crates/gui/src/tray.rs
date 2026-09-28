//! Icono en la bandeja del sistema.
//!
//! * Clic izquierdo / doble clic en el icono: muestra y trae al frente la
//!   ventana.
//! * Menú contextual: "Show CleanDesk" y "Quit".
//! * Con `Settings::minimize_to_tray` (por defecto activado), cerrar la
//!   ventana la oculta en vez de salir: el host sigue atendiendo conexiones.
//!   "Quit" del menú sí cierra la aplicación.
//!
//! `tray-icon` necesita un bucle de mensajes en el hilo que crea el icono; el
//! bucle de winit de eframe ya lo es, así que se construye dentro de
//! `CleanDeskApp::new`. Los eventos llegan por callbacks en otro hilo y se
//! reenvían por un canal, despertando a egui con `request_repaint`.

use std::sync::mpsc;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};

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
    pub fn new(ctx: egui::Context) -> Result<Self, String> {
        let menu = Menu::new();
        let show = MenuItem::new(tr("Show CleanDesk"), true, None);
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
                let _ = tx.send(TrayMsg::Icon(ev));
                ctx.request_repaint();
            }));
        }
        {
            let ctx = ctx.clone();
            MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
                let _ = tx.send(TrayMsg::Menu(ev));
                ctx.request_repaint();
            }));
        }

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("CleanDesk")
            .with_icon(icon)
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self { _icon: icon, show_id, quit_id, rx })
    }

    /// Drena los eventos pendientes y devuelve la acción de mayor prioridad.
    pub fn poll(&self) -> TrayAction {
        let mut action = TrayAction::None;
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                TrayMsg::Icon(TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. })
                | TrayMsg::Icon(TrayIconEvent::DoubleClick { button: MouseButton::Left, .. }) => {
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

/// Icono procedural: cuadrado redondeado esmeralda con una "C" blanca
/// (sin recursos externos). Devuelve (ancho, alto, RGBA).
pub fn icon_rgba(size: u32) -> (u32, u32, Vec<u8>) {
    let s = size as f32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let radius = s * 0.22;
    let inside_rounded = |x: f32, y: f32| -> bool {
        // Distancia al rectángulo interior (con esquinas redondeadas).
        let cx = x.clamp(radius, s - radius);
        let cy = y.clamp(radius, s - radius);
        let dx = x - cx;
        let dy = y - cy;
        dx * dx + dy * dy <= radius * radius
    };
    // "C": anillo abierto por la derecha.
    let center = s / 2.0;
    let r_outer = s * 0.30;
    let r_inner = s * 0.17;
    let inside_c = |x: f32, y: f32| -> bool {
        let dx = x - center;
        let dy = y - center;
        let d2 = dx * dx + dy * dy;
        let in_ring = d2 <= r_outer * r_outer && d2 >= r_inner * r_inner;
        // Abertura: sector a la derecha (|dy| < |dx| * 0.6 con dx > 0).
        let opening = dx > 0.0 && dy.abs() < dx * 0.6;
        in_ring && !opening
    };
    for y in 0..size {
        for x in 0..size {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let i = ((y * size + x) * 4) as usize;
            if inside_rounded(fx, fy) {
                if inside_c(fx, fy) {
                    rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
                } else {
                    rgba[i..i + 4].copy_from_slice(&[16, 185, 129, 255]);
                }
            }
        }
    }
    (size, size, rgba)
}

/// Icono de ventana para eframe (misma imagen que la bandeja).
pub fn window_icon() -> egui::IconData {
    let (w, h, rgba) = icon_rgba(64);
    egui::IconData { rgba, width: w, height: h }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_is_opaque_in_the_middle_and_transparent_at_corners() {
        let (w, h, rgba) = icon_rgba(32);
        assert_eq!((w, h), (32, 32));
        assert_eq!(rgba.len(), 32 * 32 * 4);
        // Esquina: transparente.
        assert_eq!(rgba[3], 0);
        // Centro-izquierda de la "C": blanco.
        let (x, y) = (16 - 7, 16);
        let i = (y * 32 + x) * 4;
        assert_eq!(&rgba[i..i + 4], &[255, 255, 255, 255]);
        // Abertura de la "C" a la derecha: verde.
        let (x, y) = (16 + 7, 16);
        let i = (y * 32 + x) * 4;
        assert_eq!(&rgba[i..i + 4], &[16, 185, 129, 255]);
    }
}
