//! Bounding and cleaning of free text received from a peer or a rendezvous.
//!
//! Device names, chat lines, disconnect reasons and refusal reasons all end
//! up in logs, history files and dialogs. None of those places can cope with
//! megabytes of text, control characters (log forging, terminal escapes) or
//! Unicode direction overrides (an alias that *renders* as somebody else's).
//! Every crate that surfaces peer text runs it through here first.

/// Longest name-like string (hostname, alias, OS, version) we keep.
pub const MAX_NAME_LEN: usize = 64;

/// Longest free-form reason/chat line we keep.
pub const MAX_TEXT_LEN: usize = 512;

/// Unicode format characters that render as nothing or flip text direction.
/// `char::is_control` does not cover them.
pub fn is_invisible_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    ) || (c as u32 & 0xFFFE) == 0xFFFE
}

/// Strip control and invisible characters and truncate to `max` characters
/// (not bytes, so the result is always valid UTF-8). Tabs and newlines
/// become spaces so the text stays a single line.
pub fn sanitize(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !is_invisible_format_char(*c))
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

/// [`sanitize`] with the name limit.
pub fn sanitize_name(text: &str) -> String {
    sanitize(text, MAX_NAME_LEN)
}

/// [`sanitize`] with the free-text limit.
pub fn sanitize_text(text: &str) -> String {
    sanitize(text, MAX_TEXT_LEN)
}

/// Clean every human-readable field of a [`DeviceInfo`](crate::session::DeviceInfo)
/// in place. The id is left alone: it is validated elsewhere.
pub fn sanitize_device_info(info: &mut crate::session::DeviceInfo) {
    info.alias = info.alias.as_deref().map(sanitize_name).filter(|a| !a.is_empty());
    info.hostname = sanitize_name(&info.hostname);
    info.os = sanitize_name(&info.os);
    info.app_version = sanitize_name(&info.app_version);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_and_bidi_and_truncates() {
        assert_eq!(sanitize("a\u{202E}b\x1bc", 10), "abc");
        assert_eq!(sanitize("line1\nline2\tx", 100), "line1 line2 x");
        assert_eq!(sanitize(&"é".repeat(100), 8), "é".repeat(8));
        assert_eq!(sanitize("   ", 8), "");
    }

    #[test]
    fn device_info_fields_are_bounded() {
        let mut info = crate::session::DeviceInfo {
            id: crate::RotoDeskId::new(123_456_789).unwrap(),
            alias: Some("\u{200B}".into()),
            hostname: "h".repeat(500),
            os: "Win\r\ndows".into(),
            app_version: "1".into(),
        };
        sanitize_device_info(&mut info);
        assert_eq!(info.alias, None);
        assert_eq!(info.hostname.len(), MAX_NAME_LEN);
        assert_eq!(info.os, "Win  dows");
    }
}
