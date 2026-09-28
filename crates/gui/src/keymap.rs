//! Traducción de teclas de egui a códigos de tecla virtual de Windows.
//!
//! `InputEvent::Key.code` viaja como un *Virtual-Key code* de Windows (el host
//! lo reinyecta con `SendInput`). Aquí convertimos la [`egui::Key`] lógica —y el
//! estado de los modificadores— en esos códigos. Las teclas que no sabemos
//! representar se descartan silenciosamente (mejor no inyectar nada que inyectar
//! algo incorrecto).

use egui::Key;

/// Código de tecla virtual de la tecla Shift (`VK_SHIFT`).
pub const VK_SHIFT: u32 = 0x10;
/// Código de tecla virtual de la tecla Ctrl (`VK_CONTROL`).
pub const VK_CONTROL: u32 = 0x11;
/// Código de tecla virtual de la tecla Alt (`VK_MENU`).
pub const VK_MENU: u32 = 0x12;

/// Convierte una [`egui::Key`] en su Virtual-Key code de Windows.
///
/// Devuelve `None` para teclas sin equivalente conocido; el llamador debe
/// ignorar esas pulsaciones en lugar de enviar un código inventado.
pub fn key_to_vk(key: Key) -> Option<u32> {
    // Letras: VK_A..=VK_Z coinciden con los ASCII 'A'..'Z' (0x41..=0x5A).
    let vk = match key {
        Key::A => 0x41,
        Key::B => 0x42,
        Key::C => 0x43,
        Key::D => 0x44,
        Key::E => 0x45,
        Key::F => 0x46,
        Key::G => 0x47,
        Key::H => 0x48,
        Key::I => 0x49,
        Key::J => 0x4A,
        Key::K => 0x4B,
        Key::L => 0x4C,
        Key::M => 0x4D,
        Key::N => 0x4E,
        Key::O => 0x4F,
        Key::P => 0x50,
        Key::Q => 0x51,
        Key::R => 0x52,
        Key::S => 0x53,
        Key::T => 0x54,
        Key::U => 0x55,
        Key::V => 0x56,
        Key::W => 0x57,
        Key::X => 0x58,
        Key::Y => 0x59,
        Key::Z => 0x5A,

        // Dígitos de la fila superior: VK_0..=VK_9 == ASCII '0'..'9' (0x30..=0x39).
        Key::Num0 => 0x30,
        Key::Num1 => 0x31,
        Key::Num2 => 0x32,
        Key::Num3 => 0x33,
        Key::Num4 => 0x34,
        Key::Num5 => 0x35,
        Key::Num6 => 0x36,
        Key::Num7 => 0x37,
        Key::Num8 => 0x38,
        Key::Num9 => 0x39,

        // Teclas de función.
        Key::F1 => 0x70,
        Key::F2 => 0x71,
        Key::F3 => 0x72,
        Key::F4 => 0x73,
        Key::F5 => 0x74,
        Key::F6 => 0x75,
        Key::F7 => 0x76,
        Key::F8 => 0x77,
        Key::F9 => 0x78,
        Key::F10 => 0x79,
        Key::F11 => 0x7A,
        Key::F12 => 0x7B,

        // Control / edición.
        Key::Enter => 0x0D,       // VK_RETURN
        Key::Escape => 0x1B,      // VK_ESCAPE
        Key::Backspace => 0x08,   // VK_BACK
        Key::Tab => 0x09,         // VK_TAB
        Key::Space => 0x20,       // VK_SPACE
        Key::Delete => 0x2E,      // VK_DELETE
        Key::Insert => 0x2D,      // VK_INSERT
        Key::Home => 0x24,        // VK_HOME
        Key::End => 0x23,         // VK_END
        Key::PageUp => 0x21,      // VK_PRIOR
        Key::PageDown => 0x22,    // VK_NEXT

        // Flechas.
        Key::ArrowLeft => 0x25,   // VK_LEFT
        Key::ArrowUp => 0x26,     // VK_UP
        Key::ArrowRight => 0x27,  // VK_RIGHT
        Key::ArrowDown => 0x28,   // VK_DOWN

        // Signos de puntuación con VK propio (layout US; suficiente para el MVP).
        Key::Minus => 0xBD,       // VK_OEM_MINUS
        Key::Plus | Key::Equals => 0xBB, // VK_OEM_PLUS
        Key::Comma => 0xBC,       // VK_OEM_COMMA
        Key::Period => 0xBE,      // VK_OEM_PERIOD
        Key::Semicolon => 0xBA,   // VK_OEM_1
        Key::Slash | Key::Questionmark => 0xBF, // VK_OEM_2
        Key::Backtick => 0xC0,    // VK_OEM_3
        Key::OpenBracket => 0xDB, // VK_OEM_4
        Key::Backslash | Key::Pipe => 0xDC, // VK_OEM_5
        Key::CloseBracket => 0xDD, // VK_OEM_6
        Key::Quote => 0xDE,       // VK_OEM_7

        // Resto de teclas: sin equivalente fiable, se descartan.
        _ => return None,
    };
    Some(vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_map_to_ascii_uppercase() {
        assert_eq!(key_to_vk(Key::A), Some(0x41));
        assert_eq!(key_to_vk(Key::Z), Some(0x5A));
    }

    #[test]
    fn digits_map_to_ascii_digits() {
        assert_eq!(key_to_vk(Key::Num0), Some(0x30));
        assert_eq!(key_to_vk(Key::Num9), Some(0x39));
    }

    #[test]
    fn common_control_keys() {
        assert_eq!(key_to_vk(Key::Enter), Some(0x0D));
        assert_eq!(key_to_vk(Key::Escape), Some(0x1B));
        assert_eq!(key_to_vk(Key::ArrowUp), Some(0x26));
        assert_eq!(key_to_vk(Key::F12), Some(0x7B));
    }
}
