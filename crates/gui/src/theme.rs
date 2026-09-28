//! Tema visual de CleanDesk: fondo *slate* oscuro con acento esmeralda.
//!
//! Centraliza colores, radios y espaciados para que la ventana principal, el
//! visor y los diálogos compartan el mismo lenguaje visual. Todo son valores
//! de `egui::Visuals`/`Style`; no hay recursos externos (fuentes o iconos), de
//! modo que el binario sigue siendo autocontenido.

use egui::{Color32, CornerRadius, Margin, Stroke, Style, Visuals};

// Paleta (slate / emerald).
pub const BG: Color32 = Color32::from_rgb(2, 6, 23); // slate-950
pub const PANEL: Color32 = Color32::from_rgb(15, 23, 42); // slate-900
pub const CARD: Color32 = Color32::from_rgb(11, 18, 34);
pub const WIDGET: Color32 = Color32::from_rgb(30, 41, 59); // slate-800
pub const BORDER: Color32 = Color32::from_rgb(30, 41, 59);
pub const BORDER_SOFT: Color32 = Color32::from_rgb(51, 65, 85); // slate-700
pub const TEXT: Color32 = Color32::from_rgb(241, 245, 249); // slate-100
pub const TEXT_DIM: Color32 = Color32::from_rgb(148, 163, 184); // slate-400
pub const TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139); // slate-500
pub const ACCENT: Color32 = Color32::from_rgb(52, 211, 153); // emerald-400
pub const ACCENT_STRONG: Color32 = Color32::from_rgb(16, 185, 129); // emerald-500
pub const ACCENT_DIM: Color32 = Color32::from_rgb(6, 78, 59); // emerald-900
pub const WARN: Color32 = Color32::from_rgb(251, 191, 36); // amber-400
pub const DANGER: Color32 = Color32::from_rgb(244, 63, 94); // rose-500
pub const STAR: Color32 = Color32::from_rgb(251, 191, 36);

pub const RADIUS: u8 = 12;
pub const RADIUS_SM: u8 = 8;

/// Aplica el tema al contexto. Llamar una vez al crear la app.
pub fn apply(ctx: &egui::Context) {
    let mut style: Style = (*ctx.style()).clone();
    let mut v = Visuals::dark();

    v.override_text_color = Some(TEXT);
    v.panel_fill = PANEL;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.faint_bg_color = CARD;
    v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.window_corner_radius = CornerRadius::same(RADIUS);
    v.menu_corner_radius = CornerRadius::same(RADIUS_SM);
    v.selection.bg_fill = ACCENT_DIM;
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = CARD;
    w.noninteractive.weak_bg_fill = CARD;
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_DIM);
    w.noninteractive.corner_radius = CornerRadius::same(RADIUS_SM);

    w.inactive.bg_fill = WIDGET;
    w.inactive.weak_bg_fill = WIDGET;
    w.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER_SOFT);
    w.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.inactive.corner_radius = CornerRadius::same(RADIUS_SM);

    w.hovered.bg_fill = Color32::from_rgb(40, 52, 72);
    w.hovered.weak_bg_fill = Color32::from_rgb(40, 52, 72);
    w.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    w.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.hovered.corner_radius = CornerRadius::same(RADIUS_SM);

    w.active.bg_fill = ACCENT_DIM;
    w.active.weak_bg_fill = ACCENT_DIM;
    w.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    w.active.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.active.corner_radius = CornerRadius::same(RADIUS_SM);

    w.open.bg_fill = WIDGET;
    w.open.weak_bg_fill = WIDGET;
    w.open.bg_stroke = Stroke::new(1.0_f32, BORDER_SOFT);
    w.open.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.open.corner_radius = CornerRadius::same(RADIUS_SM);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.window_margin = Margin::same(16);
    style.spacing.interact_size.y = 28.0;
    ctx.set_style(style);
}

/// Marco de tarjeta (fondo `CARD`, borde `BORDER`, radio `RADIUS`).
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(18))
}

/// Tarjeta destacada con borde esmeralda (la de "Tu dirección").
pub fn card_accent() -> egui::Frame {
    card().stroke(Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(52, 211, 153, 80)))
}

/// Tarjeta pequeña de la rejilla de dispositivos.
pub fn device_card(hovered: bool) -> egui::Frame {
    let stroke = if hovered { ACCENT } else { BORDER };
    egui::Frame::new()
        .fill(Color32::from_rgb(6, 11, 25))
        .stroke(Stroke::new(1.0_f32, stroke))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(14))
}

/// Etiqueta de sección en mayúsculas, pequeña y con color de acento/atenuado.
pub fn section_label(ui: &mut egui::Ui, text: &str, accent: bool) {
    let color = if accent { ACCENT } else { TEXT_DIM };
    ui.label(
        egui::RichText::new(text.to_uppercase())
            .size(11.0)
            .strong()
            .color(color),
    );
}

/// Botón primario (relleno esmeralda, texto oscuro).
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).strong().color(BG))
        .fill(ACCENT_STRONG)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Botón secundario (borde esmeralda suave).
pub fn ghost_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(ACCENT))
        .fill(Color32::from_rgba_unmultiplied(16, 185, 129, 24))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(52, 211, 153, 90)))
        .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Botón peligroso (rojo) para desconectar/finalizar.
pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).strong().color(TEXT))
        .fill(Color32::from_rgb(120, 30, 50))
        .stroke(Stroke::new(1.0_f32, DANGER))
        .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Punto de estado coloreado seguido de un texto.
pub fn status_dot(ui: &mut egui::Ui, color: Color32, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
    ui.label(egui::RichText::new(text).color(TEXT_DIM).size(12.0));
}

/// Dibuja el ID en tres grupos, con el grupo central en color de acento.
pub fn big_id(ui: &mut egui::Ui, id: cleandesk_proto::CleanDeskId) {
    let s = id.to_string();
    let groups: Vec<&str> = s.split(' ').collect();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for (i, g) in groups.iter().enumerate() {
            let color = if i == 1 { ACCENT } else { TEXT };
            ui.label(egui::RichText::new(*g).monospace().size(34.0).strong().color(color));
        }
    });
}
