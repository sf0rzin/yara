//! Reading two-factor enrollment QR codes.
//!
//! Decoding happens here, in Rust, rather than in the interface. A TOTP QR code
//! carries the shared secret — the long-lived credential, not the six digits it
//! produces — so it should never become a JavaScript string sitting in a heap
//! that cannot be wiped. The frontend hands over image bytes and gets back a
//! description of what was found, never the seed.

use std::io::Cursor;

use image::ImageReader;

use crate::error::{Error, Result};
use crate::totp::TotpConfig;

/// Largest image accepted, to bound the work done on untrusted input.
const MAX_PIXELS: u32 = 40_000_000;

/// Finds a two-factor enrollment code in an image.
///
/// Screenshots often catch more than the QR code — a whole browser window, say
/// — so every QR code in the image is considered and the first `otpauth://` one
/// wins. If codes are found but none of them are enrollment codes, that is
/// reported separately from finding nothing at all, because the two mean very
/// different things to someone trying to work out what went wrong.
pub fn decode_enrollment(image_bytes: &[u8]) -> Result<TotpConfig> {
    // The size is read out of the header and judged before anything is
    // decoded. Checking after `load_from_memory` returned was checking after
    // the surface had already been allocated, and the numbers make that a real
    // problem: a 50000x50000 PNG is a few hundred kilobytes on the wire and
    // tens of gigabytes decoded. With `panic = "abort"` a failed allocation of
    // that size is a crash, and a crash dump of this process is a disclosure.
    let (width, height) = reader(image_bytes)?
        .into_dimensions()
        .map_err(|_| Error::ImageDecode)?;

    if width == 0 || height == 0 || width.saturating_mul(height) > MAX_PIXELS {
        return Err(Error::ImageDecode);
    }

    let image = reader(image_bytes)?
        .decode()
        .map_err(|_| Error::ImageDecode)?;
    decode_luma(image.to_luma8())
}

/// A reader over the bytes with the format already sniffed.
///
/// Built twice per decode — once to read the header, once to decode — which
/// costs a second look at a few bytes and buys the ordering above.
fn reader(image_bytes: &[u8]) -> Result<ImageReader<Cursor<&[u8]>>> {
    ImageReader::new(Cursor::new(image_bytes))
        .with_guessed_format()
        .map_err(|_| Error::ImageDecode)
}

/// Finds an enrollment code in raw RGBA pixels.
///
/// The system clipboard hands over decoded pixels rather than an encoded file,
/// so a screenshot pasted straight from Win+Shift+S arrives this way.
pub fn decode_enrollment_rgba(rgba: &[u8], width: u32, height: u32) -> Result<TotpConfig> {
    if width == 0 || height == 0 || width.saturating_mul(height) > MAX_PIXELS {
        return Err(Error::ImageDecode);
    }

    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(Error::ImageDecode)?;

    if rgba.len() < expected {
        return Err(Error::ImageDecode);
    }

    let buffer: image::RgbaImage =
        image::ImageBuffer::from_raw(width, height, rgba[..expected].to_vec())
            .ok_or(Error::ImageDecode)?;

    decode_luma(image::DynamicImage::ImageRgba8(buffer).to_luma8())
}

fn decode_luma(luma: image::GrayImage) -> Result<TotpConfig> {
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        return Err(Error::NoQrCode);
    }

    let mut saw_a_code = false;

    for grid in grids {
        let Ok((_meta, content)) = grid.decode() else {
            continue;
        };
        saw_a_code = true;

        if content
            .trim()
            .to_ascii_lowercase()
            .starts_with("otpauth://")
        {
            return TotpConfig::from_uri(content.trim());
        }
    }

    Err(if saw_a_code {
        Error::QrNotOtpauth
    } else {
        Error::NoQrCode
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::TotpAlgorithm;
    use image::{ImageBuffer, Luma};
    use qrcode::QrCode;

    /// Renders text as a QR code PNG.
    ///
    /// Built by hand from the module grid rather than through `qrcode`'s image
    /// feature, which would pin this crate to whichever `image` version that
    /// feature happens to depend on.
    fn qr_png(content: &str, scale: u32) -> Vec<u8> {
        let code = QrCode::new(content.as_bytes()).unwrap();
        let modules = code.to_colors();
        let width = code.width() as u32;

        // A quiet zone of four modules is required for reliable detection.
        let quiet = 4;
        let side = (width + quiet * 2) * scale;

        let image = ImageBuffer::from_fn(side, side, |x, y| {
            let mx = (x / scale) as i64 - quiet as i64;
            let my = (y / scale) as i64 - quiet as i64;

            if mx < 0 || my < 0 || mx >= width as i64 || my >= width as i64 {
                return Luma([255u8]);
            }

            let module = modules[(my as u32 * width + mx as u32) as usize];
            if module == qrcode::Color::Dark {
                Luma([0u8])
            } else {
                Luma([255u8])
            }
        });

        let mut png = Vec::new();
        image
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        png
    }

    #[test]
    fn reads_a_standard_enrollment_code() {
        let png = qr_png(
            "otpauth://totp/GitHub:anthony?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub",
            8,
        );

        let config = decode_enrollment(&png).unwrap();
        assert_eq!(config.issuer.as_deref(), Some("GitHub"));
        assert_eq!(config.account.as_deref(), Some("anthony"));
        assert_eq!(config.secret.expose(), "GEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn carries_non_default_parameters_through() {
        let png = qr_png(
            "otpauth://totp/ACME:me?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60",
            8,
        );

        let config = decode_enrollment(&png).unwrap();
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 60);
    }

    #[test]
    fn the_decoded_code_generates_the_same_digits_as_the_secret() {
        let png = qr_png("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ", 8);
        let scanned = decode_enrollment(&png).unwrap();

        assert_eq!(
            scanned.generate_at(59).unwrap(),
            TotpConfig::new("GEZDGNBVGY3TQOJQ").generate_at(59).unwrap()
        );
    }

    #[test]
    fn a_small_scale_code_still_decodes() {
        // Roughly what a QR looks like in a screenshot of a browser window.
        let png = qr_png("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ", 3);
        assert!(decode_enrollment(&png).is_ok());
    }

    #[test]
    fn a_qr_code_that_is_not_an_enrollment_code_is_reported_as_such() {
        let png = qr_png("https://example.com", 8);
        assert!(matches!(decode_enrollment(&png), Err(Error::QrNotOtpauth)));
    }

    #[test]
    fn an_image_with_no_qr_code_is_reported_as_such() {
        let blank = ImageBuffer::from_pixel(200, 200, Luma([255u8]));
        let mut png = Vec::new();
        blank
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();

        assert!(matches!(decode_enrollment(&png), Err(Error::NoQrCode)));
    }

    #[test]
    fn reads_a_code_from_raw_clipboard_pixels() {
        let png = qr_png("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ", 8);
        let rgba = image::load_from_memory(&png).unwrap().to_rgba8();
        let (width, height) = rgba.dimensions();

        let config = decode_enrollment_rgba(rgba.as_raw(), width, height).unwrap();
        assert_eq!(config.secret.expose(), "GEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn a_truncated_pixel_buffer_is_rejected_rather_than_panicking() {
        assert!(matches!(
            decode_enrollment_rgba(&[0u8; 16], 100, 100),
            Err(Error::ImageDecode)
        ));
    }

    #[test]
    fn zero_sized_pixel_buffers_are_rejected() {
        assert!(matches!(
            decode_enrollment_rgba(&[], 0, 0),
            Err(Error::ImageDecode)
        ));
    }

    /// One PNG chunk: length, type, data, CRC over type and data.
    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(data.len() + 12);
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());

        let mut covered = kind.to_vec();
        covered.extend_from_slice(data);
        chunk.extend_from_slice(&covered);
        chunk.extend_from_slice(&crc32(&covered).to_be_bytes());
        chunk
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A well-formed PNG whose header claims 50000x50000.
    ///
    /// Under a hundred bytes on the wire, 2.5 gigapixels decoded.
    fn enormous_png() -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&50_000u32.to_be_bytes());
        header.extend_from_slice(&50_000u32.to_be_bytes());
        header.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit greyscale

        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend_from_slice(&png_chunk(b"IHDR", &header));
        png.extend_from_slice(&png_chunk(b"IDAT", &[0x78, 0x01, 0x01, 0x00, 0x00]));
        png.extend_from_slice(&png_chunk(b"IEND", &[]));
        png
    }

    #[test]
    fn an_image_that_declares_itself_enormous_is_refused_from_its_header() {
        // The size limit is only a limit if it is applied before the pixels
        // are allocated. This file is smaller than this comment and would
        // decode to tens of gigabytes; under `panic = "abort"` the allocation
        // failing is a crash, and a crash dump of this process is a
        // disclosure path.
        let png = enormous_png();
        assert!(png.len() < 100, "the point is the amplification");

        let started = std::time::Instant::now();
        assert!(matches!(decode_enrollment(&png), Err(Error::ImageDecode)));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the refusal has to come from the header, not from trying it"
        );
    }

    #[test]
    fn a_zero_sized_image_is_rejected() {
        let mut header = Vec::new();
        header.extend_from_slice(&0u32.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes());
        header.extend_from_slice(&[8, 0, 0, 0, 0]);

        let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        png.extend_from_slice(&png_chunk(b"IHDR", &header));
        png.extend_from_slice(&png_chunk(b"IEND", &[]));

        assert!(matches!(decode_enrollment(&png), Err(Error::ImageDecode)));
    }

    #[test]
    fn something_that_is_not_an_image_is_rejected() {
        assert!(matches!(
            decode_enrollment(b"this is not an image"),
            Err(Error::ImageDecode)
        ));
    }

    #[test]
    fn an_enrollment_code_with_an_undecodable_secret_is_rejected() {
        let png = qr_png("otpauth://totp/x?secret=not!base32", 8);
        assert!(matches!(decode_enrollment(&png), Err(Error::InvalidBase32)));
    }

    #[test]
    fn a_hotp_code_is_rejected_rather_than_silently_misread() {
        let png = qr_png("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1", 8);
        assert!(matches!(
            decode_enrollment(&png),
            Err(Error::InvalidOtpUri(_))
        ));
    }
}
