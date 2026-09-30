//! Tema visual de CleanDesk: fondo claro con acento verde.
//!
//! Centraliza colores, radios y espaciados para que la ventana principal, el
//! visor y los diálogos compartan el mismo lenguaje visual. Todo son valores
//! de `egui::Visuals`/`Style`; no hay recursos externos (fuentes o iconos), de
//! modo que el binario sigue siendo autocontenido.

use egui::{Color32, CornerRadius, Margin, Stroke, Style, Visuals};

// Paleta (claro / verde).
pub const BG: Color32 = Color32::from_rgb(246, 248, 247); // fondo de página
pub const PANEL: Color32 = Color32::from_rgb(255, 255, 255); // cabecera, pie, ventanas
pub const CARD: Color32 = Color32::from_rgb(255, 255, 255);
pub const CARD_TINT: Color32 = Color32::from_rgb(232, 248, 242); // tarjetas verdosas
pub const WIDGET: Color32 = Color32::from_rgb(243, 245, 244);
pub const BORDER: Color32 = Color32::from_rgb(226, 232, 228);
pub const BORDER_SOFT: Color32 = Color32::from_rgb(203, 213, 206);
pub const TEXT: Color32 = Color32::from_rgb(23, 33, 28);
pub const TEXT_DIM: Color32 = Color32::from_rgb(86, 100, 92);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(140, 152, 145);
pub const ACCENT: Color32 = Color32::from_rgb(0, 155, 114); // verde principal
pub const ACCENT_STRONG: Color32 = Color32::from_rgb(0, 107, 80);
pub const ACCENT_LIGHT: Color32 = Color32::from_rgb(22, 190, 143);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(218, 245, 235); // fondos suaves verdes
pub const WARN: Color32 = Color32::from_rgb(217, 119, 6);
pub const DANGER: Color32 = Color32::from_rgb(220, 38, 38);
pub const STAR: Color32 = Color32::from_rgb(245, 158, 11);
pub const ONLINE: Color32 = Color32::from_rgb(34, 197, 94);
pub const OFFLINE: Color32 = Color32::from_rgb(148, 163, 184);

pub const RADIUS: u8 = 14;
pub const RADIUS_SM: u8 = 9;

/// Aplica el tema al contexto. Llamar una vez al crear la app.
pub fn apply(ctx: &egui::Context) {
    let mut style: Style = (*ctx.style()).clone();
    let mut v = Visuals::light();

    v.override_text_color = Some(TEXT);
    v.panel_fill = PANEL;
    v.window_fill = PANEL;
    v.extreme_bg_color = Color32::WHITE;
    v.faint_bg_color = WIDGET;
    v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.window_corner_radius = CornerRadius::same(RADIUS);
    v.menu_corner_radius = CornerRadius::same(RADIUS_SM);
    v.window_shadow.color = Color32::from_black_alpha(28);
    v.popup_shadow.color = Color32::from_black_alpha(20);
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

    w.hovered.bg_fill = ACCENT_DIM;
    w.hovered.weak_bg_fill = ACCENT_DIM;
    w.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_LIGHT);
    w.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    w.hovered.corner_radius = CornerRadius::same(RADIUS_SM);

    w.active.bg_fill = Color32::from_rgb(200, 232, 212);
    w.active.weak_bg_fill = Color32::from_rgb(200, 232, 212);
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
    style.spacing.button_padding = egui::vec2(14.0, 7.0);
    style.spacing.window_margin = Margin::same(18);
    style.spacing.interact_size.y = 30.0;
    ctx.set_style(style);
}

/// Marco de tarjeta blanca con borde suave.
pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(18))
        .shadow(egui::epaint::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(10),
        })
}

/// Tarjeta con tinte verde (las tarjetas de acción del inicio).
pub fn card_tinted() -> egui::Frame {
    card()
        .fill(CARD_TINT)
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(214, 232, 220)))
}

/// Tarjeta de la rejilla de sesiones recientes (sin margen interior: la
/// miniatura ocupa todo el ancho y el pie lleva su propio relleno).
pub fn device_card(hovered: bool) -> egui::Frame {
    let stroke = if hovered { ACCENT_LIGHT } else { BORDER };
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, stroke))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::ZERO)
        .shadow(egui::epaint::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: Color32::from_black_alpha(10),
        })
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

/// Botón primario (relleno verde, texto blanco).
pub fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.to_owned())
            .strong()
            .color(Color32::WHITE),
    )
    .fill(ACCENT)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Botón secundario (blanco con borde y texto verde).
pub fn ghost_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(ACCENT))
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0_f32, BORDER_SOFT))
        .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Botón "pastilla" blanco con texto oscuro (tarjetas de acción).
pub fn pill_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).color(TEXT))
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0_f32, BORDER_SOFT))
        .corner_radius(CornerRadius::same(20))
}

/// Botón peligroso (rojo) para desconectar/finalizar.
pub fn danger_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.to_owned())
            .strong()
            .color(Color32::WHITE),
    )
    .fill(DANGER)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_SM))
}

/// Punto de estado coloreado seguido de un texto.
pub fn status_dot(ui: &mut egui::Ui, color: Color32, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 9.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.5, color);
    if !text.is_empty() {
        ui.label(egui::RichText::new(text).color(TEXT_DIM).size(13.0));
    }
}

/// Dibuja el ID en tres grupos grandes en verde.
pub fn big_id(ui: &mut egui::Ui, id: cleandesk_proto::CleanDeskId) {
    let s = id.to_string();
    ui.label(egui::RichText::new(s).size(38.0).strong().color(ACCENT));
}

/// Hoja decorativa (dos arcos rellenos) en verde translúcido.
pub fn leaf(painter: &egui::Painter, center: egui::Pos2, size: f32, alpha: u8) {
    let color = Color32::from_rgba_unmultiplied(31, 138, 74, alpha);
    let mut pts = Vec::with_capacity(40);
    for i in 0..=20 {
        let t = i as f32 / 20.0;
        let x = center.x - size * 0.5 + t * size;
        let y = center.y - (t * std::f32::consts::PI).sin() * size * 0.35;
        pts.push(egui::pos2(x, y));
    }
    for i in (0..=20).rev() {
        let t = i as f32 / 20.0;
        let x = center.x - size * 0.5 + t * size;
        let y = center.y + (t * std::f32::consts::PI).sin() * size * 0.35;
        pts.push(egui::pos2(x, y));
    }
    painter.add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
}

/// Icono de monitor dibujado con primitivas (pantalla + pie).
pub fn monitor_icon(painter: &egui::Painter, center: egui::Pos2, size: f32, color: Color32) {
    let w = size;
    let h = size * 0.66;
    let screen = egui::Rect::from_center_size(
        egui::pos2(center.x, center.y - size * 0.08),
        egui::vec2(w, h),
    );
    painter.rect_stroke(
        screen,
        size * 0.12,
        Stroke::new((size * 0.08).max(1.5), color),
        egui::StrokeKind::Inside,
    );
    let stand_y = screen.bottom() + size * 0.14;
    painter.line_segment(
        [
            egui::pos2(center.x, screen.bottom()),
            egui::pos2(center.x, stand_y),
        ],
        Stroke::new((size * 0.08).max(1.5), color),
    );
    painter.line_segment(
        [
            egui::pos2(center.x - size * 0.22, stand_y),
            egui::pos2(center.x + size * 0.22, stand_y),
        ],
        Stroke::new((size * 0.08).max(1.5), color),
    );
}

/// Generated brand asset shared by the header, window and installer.
pub fn brand(ui: &mut egui::Ui, size: f32) {
    let id = egui::Id::new("cleandesk-brand-texture");
    let texture = ui
        .ctx()
        .data_mut(|data| data.get_temp::<egui::TextureHandle>(id));
    let texture = texture.unwrap_or_else(|| {
        let img = image::load_from_memory(include_bytes!("../assets/icon-256.png"))
            .expect("embedded brand PNG")
            .to_rgba8();
        let color = egui::ColorImage::from_rgba_unmultiplied(
            [img.width() as usize, img.height() as usize],
            img.as_raw(),
        );
        let texture = ui
            .ctx()
            .load_texture("cleandesk-brand", color, egui::TextureOptions::LINEAR);
        ui.ctx()
            .data_mut(|data| data.insert_temp(id, texture.clone()));
        texture
    });
    ui.image((texture.id(), egui::vec2(size, size)));
}

/// Small action symbols painted with geometry, independent of installed fonts.
pub fn action_icon(painter: &egui::Painter, center: egui::Pos2, kind: &str) {
    let stroke = Stroke::new(2.0_f32, ACCENT);
    if kind == "discover" {
        painter.circle_stroke(center, 9.0, stroke);
        painter.circle_stroke(center, 4.0, stroke);
        painter.circle_filled(center, 1.5, ACCENT);
    } else if kind == "contacts" {
        painter.circle_stroke(center + egui::vec2(0.0, -5.0), 4.0, stroke);
        painter.rect_stroke(
            egui::Rect::from_center_size(center + egui::vec2(0.0, 6.0), egui::vec2(16.0, 9.0)),
            4.0,
            stroke,
            egui::StrokeKind::Inside,
        );
    } else if kind == "access" {
        monitor_icon(painter, center, 22.0, ACCENT);
    } else {
        for offset in [egui::vec2(0.0, 9.0), egui::vec2(9.0, 0.0)] {
            painter.line_segment([center - offset, center + offset], stroke);
        }
    }
}
