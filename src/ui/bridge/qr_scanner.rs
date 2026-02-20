// QR Code Scanner Module
// Supports: screen capture, clipboard paste, and file browse

use image::{DynamicImage, GrayImage};
use rqrr::PreparedImage;
use arboard::Clipboard;

/// Decoded QR result — either a parsed otpauth URI or a raw secret string
pub struct QrResult {
    pub account: String,
    pub secret: String,
    pub issuer: String,
}

// ─── Core decoder ───────────────────────────────────────────────────────────

/// Decode a QR code from any DynamicImage
fn decode_qr_from_image(img: &DynamicImage) -> Result<String, String> {
    let gray: GrayImage = img.to_luma8();
    let mut prepared = PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        return Err("No QR code found in the image".into());
    }

    let (_meta, content) = grids[0]
        .decode()
        .map_err(|e| format!("Failed to decode QR code: {:?}", e))?;

    Ok(content)
}

/// Parse an otpauth:// URI into (account, secret, issuer)
/// Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
pub fn parse_otpauth_uri(uri: &str) -> Option<QrResult> {
    if !uri.starts_with("otpauth://totp/") && !uri.starts_with("otpauth://hotp/") {
        // Not an otpauth URI — treat whole string as a raw secret
        let cleaned = uri.replace(' ', "").replace('-', "").to_uppercase();
        if !cleaned.is_empty() {
            return Some(QrResult {
                account: String::new(),
                secret: cleaned,
                issuer: String::new(),
            });
        }
        return None;
    }

    // Split off the query string
    let without_scheme = if uri.starts_with("otpauth://totp/") {
        &uri["otpauth://totp/".len()..]
    } else {
        &uri["otpauth://hotp/".len()..]
    };

    let (label_part, query_part) = if let Some(idx) = without_scheme.find('?') {
        (&without_scheme[..idx], &without_scheme[idx + 1..])
    } else {
        (without_scheme, "")
    };

    // URL-decode the label
    let label = url_decode(label_part);

    // Parse the label: could be "Issuer:Account" or just "Account"
    let (label_issuer, account) = if let Some(colon_idx) = label.find(':') {
        (
            label[..colon_idx].trim().to_string(),
            label[colon_idx + 1..].trim().to_string(),
        )
    } else {
        (String::new(), label.trim().to_string())
    };

    // Parse query parameters
    let mut secret = String::new();
    let mut issuer = String::new();

    for param in query_part.split('&') {
        if let Some(eq_idx) = param.find('=') {
            let key = &param[..eq_idx];
            let value = url_decode(&param[eq_idx + 1..]);
            match key.to_lowercase().as_str() {
                "secret" => secret = value.replace(' ', "").replace('-', "").to_uppercase(),
                "issuer" => issuer = value,
                _ => {}
            }
        }
    }

    // Use label issuer if query issuer is empty
    if issuer.is_empty() && !label_issuer.is_empty() {
        issuer = label_issuer;
    }

    if secret.is_empty() {
        return None;
    }

    Some(QrResult {
        account,
        secret,
        issuer,
    })
}

/// Simple URL percent-decoding
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

// ─── Scan from screen capture ───────────────────────────────────────────────

/// Capture all screens using xcap, combine them, and scan for QR codes.
/// Uses a simple full-screen approach: captures the primary monitor.
pub fn scan_qr_from_screen() -> Result<QrResult, String> {
    println!("[QR] Starting screen capture...");

    // Capture the primary monitor
    let monitors = xcap::Monitor::all().map_err(|e| format!("Failed to enumerate monitors: {:?}", e))?;

    if monitors.is_empty() {
        return Err("No monitors found".into());
    }

    // Try each monitor for a QR code
    for (i, monitor) in monitors.iter().enumerate() {
        println!("[QR] Capturing monitor {} ({:?}x{:?})", i, monitor.width(), monitor.height());

        let capture = monitor
            .capture_image()
            .map_err(|e| format!("Failed to capture monitor {}: {:?}", i, e))?;

        // Convert xcap image to image::DynamicImage
        let width = capture.width();
        let height = capture.height();
        let raw_pixels = capture.into_raw();

        // xcap produces RGBA pixels
        if let Some(img_buf) = image::RgbaImage::from_raw(width, height, raw_pixels) {
            let dynamic = DynamicImage::ImageRgba8(img_buf);

            match decode_qr_from_image(&dynamic) {
                Ok(content) => {
                    println!("[QR] Found QR code on monitor {}: {}", i, &content[..content.len().min(50)]);
                    return parse_otpauth_uri(&content)
                        .ok_or_else(|| "QR code found but does not contain valid TOTP data".into());
                }
                Err(_) => {
                    println!("[QR] No QR code found on monitor {}", i);
                    continue;
                }
            }
        }
    }

    Err("No QR code found on any screen. Make sure a QR code is visible on your screen.".into())
}

// ─── Scan from clipboard image ──────────────────────────────────────────────

/// Read an image from the clipboard and scan for QR codes.
pub fn scan_qr_from_clipboard() -> Result<QrResult, String> {
    println!("[QR] Reading image from clipboard...");

    let mut clipboard = Clipboard::new()
        .map_err(|e| format!("Failed to access clipboard: {:?}", e))?;

    let img_data = clipboard
        .get_image()
        .map_err(|_| "No image found in clipboard. Copy a QR code image first.".to_string())?;

    println!("[QR] Clipboard image: {}x{}", img_data.width, img_data.height);

    // arboard gives us RGBA bytes
    let width = img_data.width as u32;
    let height = img_data.height as u32;
    let rgba_bytes: Vec<u8> = img_data.bytes.into_owned();

    let img_buf = image::RgbaImage::from_raw(width, height, rgba_bytes)
        .ok_or("Failed to create image from clipboard data")?;

    let dynamic = DynamicImage::ImageRgba8(img_buf);

    let content = decode_qr_from_image(&dynamic)?;
    println!("[QR] Decoded from clipboard: {}", &content[..content.len().min(50)]);

    parse_otpauth_uri(&content)
        .ok_or_else(|| "QR code found but does not contain valid TOTP data".into())
}

// ─── Scan from file ─────────────────────────────────────────────────────────

/// Open a file dialog, load the selected image, and scan for QR codes.
pub fn scan_qr_from_file() -> Result<QrResult, String> {

    let file = rfd::FileDialog::new()
        .set_title("Select QR Code Image")
        .add_filter("Images", &["png", "jpg", "jpeg", "bmp", "gif", "webp"])
        .pick_file();

    let path = file.ok_or("No file selected")?;

    let img = image::open(&path)
        .map_err(|e| format!("Failed to open image: {:?}", e))?;

    let content = decode_qr_from_image(&img)?;

    parse_otpauth_uri(&content)
        .ok_or_else(|| "QR code found but does not contain valid TOTP data".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_otpauth_uri_full() {
        let uri = "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let result = parse_otpauth_uri(uri).unwrap();
        assert_eq!(result.account, "user@example.com");
        assert_eq!(result.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(result.issuer, "GitHub");
    }

    #[test]
    fn test_parse_otpauth_uri_no_issuer_param() {
        let uri = "otpauth://totp/Google:alice@gmail.com?secret=ABC123";
        let result = parse_otpauth_uri(uri).unwrap();
        assert_eq!(result.account, "alice@gmail.com");
        assert_eq!(result.secret, "ABC123");
        assert_eq!(result.issuer, "Google");
    }

    #[test]
    fn test_parse_otpauth_uri_simple_label() {
        let uri = "otpauth://totp/MyApp?secret=MYSECRETKEY";
        let result = parse_otpauth_uri(uri).unwrap();
        assert_eq!(result.account, "MyApp");
        assert_eq!(result.secret, "MYSECRETKEY");
        assert_eq!(result.issuer, "");
    }

    #[test]
    fn test_parse_raw_secret() {
        let raw = "JBSWY3DPEHPK3PXP";
        let result = parse_otpauth_uri(raw).unwrap();
        assert_eq!(result.account, "");
        assert_eq!(result.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(result.issuer, "");
    }

    #[test]
    fn test_parse_otpauth_with_spaces_in_secret() {
        let uri = "otpauth://totp/Test?secret=JBSW Y3DP EHPK 3PXP";
        let result = parse_otpauth_uri(uri).unwrap();
        assert_eq!(result.secret, "JBSWY3DPEHPK3PXP");
    }
}
