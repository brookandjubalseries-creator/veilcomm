//! Steganographic encoding/decoding
//!
//! Embeds encrypted message payloads in BMP image files using LSB steganography.
//! This makes VeilComm traffic look like image file sharing rather than encrypted
//! chat messages, providing a layer of traffic obfuscation.

use rand::RngCore;
use std::fmt;

// ---------------------------------------------------------------------------
// BMP constants
// ---------------------------------------------------------------------------

/// Size of the BMP file header (magic + file size + reserved + pixel offset).
const BMP_FILE_HEADER_SIZE: u32 = 14;

/// Size of the BITMAPINFOHEADER DIB header.
const DIB_HEADER_SIZE: u32 = 40;

/// Combined header size that precedes pixel data.
const HEADERS_SIZE: u32 = BMP_FILE_HEADER_SIZE + DIB_HEADER_SIZE;

/// Bits per pixel for 24-bit RGB.
const BITS_PER_PIXEL: u16 = 24;

/// Bytes per pixel (R, G, B).
const BYTES_PER_PIXEL: u32 = 3;

/// Number of LSBs we embed per pixel (one per colour channel).
const BITS_PER_PIXEL_EMBEDDED: usize = 3;

/// Number of bits used to store the payload length prefix (4 bytes = 32 bits).
const LENGTH_PREFIX_BITS: usize = 32;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during steganographic operations.
#[derive(Debug, Clone)]
pub enum StegoError {
    /// The input data is not a valid BMP file.
    InvalidFormat(String),
    /// The payload exceeds the carrier image capacity.
    PayloadTooLarge {
        /// Maximum bytes the image can hold.
        capacity: usize,
        /// Bytes the caller attempted to embed.
        needed: usize,
    },
    /// Extraction of the hidden payload failed.
    ExtractionFailed(String),
}

impl fmt::Display for StegoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StegoError::InvalidFormat(msg) => write!(f, "invalid BMP format: {msg}"),
            StegoError::PayloadTooLarge { capacity, needed } => {
                write!(
                    f,
                    "payload too large: image can hold {capacity} bytes but {needed} bytes needed"
                )
            }
            StegoError::ExtractionFailed(msg) => write!(f, "extraction failed: {msg}"),
        }
    }
}

impl std::error::Error for StegoError {}

// ---------------------------------------------------------------------------
// Helper: little-endian integer encoding
// ---------------------------------------------------------------------------

/// Write a `u16` as two little-endian bytes into `buf` at `offset`.
#[inline]
fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Write a `u32` as four little-endian bytes into `buf` at `offset`.
#[inline]
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Read a `u16` from two little-endian bytes in `buf` at `offset`.
#[inline]
fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a `u32` from four little-endian bytes in `buf` at `offset`.
#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

// ---------------------------------------------------------------------------
// BMP geometry helpers
// ---------------------------------------------------------------------------

/// Compute the number of padding bytes appended to each row so that row size
/// is a multiple of 4 bytes.
#[inline]
fn row_padding(width: u32) -> u32 {
    let row_bytes = width * BYTES_PER_PIXEL;
    (4 - (row_bytes % 4)) % 4
}

/// Compute the total size of the pixel data section (including row padding).
#[inline]
fn pixel_data_size(width: u32, height: u32) -> u32 {
    let row_bytes = width * BYTES_PER_PIXEL + row_padding(width);
    row_bytes * height
}

/// Choose the smallest square-ish image dimensions that provide enough pixels
/// to hold `total_bits` of embedded data. The width is chosen first and the
/// height is derived so that `width * height >= pixels_needed`.
fn dimensions_for_bits(total_bits: usize) -> (u32, u32) {
    let pixels_needed = (total_bits + BITS_PER_PIXEL_EMBEDDED - 1) / BITS_PER_PIXEL_EMBEDDED;
    // At minimum 1x1.
    let pixels_needed = pixels_needed.max(1) as u32;

    // Use a square root to get a roughly square image.
    let side = (pixels_needed as f64).sqrt().ceil() as u32;
    let width = side;
    // Height must be enough so that width * height >= pixels_needed.
    let height = (pixels_needed + width - 1) / width;
    (width, height)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Calculate the maximum number of payload bytes that can be embedded in a
/// BMP image of the given pixel dimensions.
///
/// This accounts for the 32-bit length prefix that is always embedded before
/// the payload itself.
pub fn capacity(width: u32, height: u32) -> usize {
    let total_pixels = (width as usize) * (height as usize);
    let total_embeddable_bits = total_pixels * BITS_PER_PIXEL_EMBEDDED;
    // Subtract the 32 bits used for the length prefix.
    let payload_bits = total_embeddable_bits.saturating_sub(LENGTH_PREFIX_BITS);
    payload_bits / 8
}

/// Encode a payload into a freshly generated BMP image.
///
/// The function creates a carrier image just large enough to hold the payload,
/// fills it with random pixel data, and then embeds the payload using LSB
/// steganography (1 bit per colour channel, 3 bits per pixel).
///
/// Returns the complete BMP file as a byte vector.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let total_bits = LENGTH_PREFIX_BITS + payload_len * 8;
    let (width, height) = dimensions_for_bits(total_bits);

    // Sanity check (should always pass given how we chose dimensions).
    debug_assert!(capacity(width, height) >= payload_len);

    let px_data_size = pixel_data_size(width, height);
    let file_size = HEADERS_SIZE + px_data_size;

    let mut bmp = vec![0u8; file_size as usize];

    // ----- BMP file header (14 bytes) -----
    bmp[0] = b'B';
    bmp[1] = b'M';
    write_u32_le(&mut bmp, 2, file_size);
    // bytes 6..9 are reserved (already zero)
    write_u32_le(&mut bmp, 10, HEADERS_SIZE);

    // ----- DIB header (BITMAPINFOHEADER, 40 bytes) -----
    write_u32_le(&mut bmp, 14, DIB_HEADER_SIZE); // header size
    write_u32_le(&mut bmp, 18, width); // image width
    write_u32_le(&mut bmp, 22, height); // image height
    write_u16_le(&mut bmp, 26, 1); // colour planes
    write_u16_le(&mut bmp, 28, BITS_PER_PIXEL); // bits per pixel
    write_u32_le(&mut bmp, 30, 0); // compression (BI_RGB = 0)
    write_u32_le(&mut bmp, 34, px_data_size); // image size
    write_u32_le(&mut bmp, 38, 2835); // horizontal resolution (72 DPI)
    write_u32_le(&mut bmp, 42, 2835); // vertical resolution (72 DPI)
    write_u32_le(&mut bmp, 46, 0); // colours in palette
    write_u32_le(&mut bmp, 50, 0); // important colours

    // ----- Fill pixel data with random bytes -----
    let pixel_start = HEADERS_SIZE as usize;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bmp[pixel_start..]);

    // ----- Embed data via LSB -----
    // Build a single bit stream: 32-bit length prefix (LE) followed by payload.
    let length_bytes = (payload_len as u32).to_le_bytes();

    // We iterate over pixel channels in row-major order, skipping the padding
    // bytes at the end of each row, embedding one bit per channel.
    let pad = row_padding(width) as usize;
    let row_data_bytes = (width as usize) * (BYTES_PER_PIXEL as usize);

    // Collect all bits to embed.
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for &b in &length_bytes {
        for bit_idx in 0..8u8 {
            bits.push((b >> bit_idx) & 1);
        }
    }
    for &b in payload {
        for bit_idx in 0..8u8 {
            bits.push((b >> bit_idx) & 1);
        }
    }

    let mut bit_index = 0usize;
    'outer: for row in 0..height as usize {
        let row_start = pixel_start + row * (row_data_bytes + pad);
        for col_byte in 0..row_data_bytes {
            if bit_index >= bits.len() {
                break 'outer;
            }
            let pos = row_start + col_byte;
            // Clear the LSB and set it to our data bit.
            bmp[pos] = (bmp[pos] & 0xFE) | bits[bit_index];
            bit_index += 1;
        }
    }

    bmp
}

/// Decode a payload previously embedded in a BMP image via [`encode`].
///
/// Returns the extracted payload bytes, or a [`StegoError`] if the input is
/// not a valid BMP or the embedded data is inconsistent.
pub fn decode(bmp_data: &[u8]) -> Result<Vec<u8>, StegoError> {
    // ----- Validate BMP header -----
    if bmp_data.len() < HEADERS_SIZE as usize {
        return Err(StegoError::InvalidFormat(
            "data too short to contain BMP headers".into(),
        ));
    }
    if bmp_data[0] != b'B' || bmp_data[1] != b'M' {
        return Err(StegoError::InvalidFormat(
            "missing BMP magic bytes".into(),
        ));
    }

    let pixel_offset = read_u32_le(bmp_data, 10) as usize;
    let width = read_u32_le(bmp_data, 18);
    let height = read_u32_le(bmp_data, 22);
    let bpp = read_u16_le(bmp_data, 28);

    if bpp != BITS_PER_PIXEL {
        return Err(StegoError::InvalidFormat(format!(
            "unsupported bits-per-pixel: {bpp} (expected {BITS_PER_PIXEL})"
        )));
    }

    if width == 0 || height == 0 {
        return Err(StegoError::InvalidFormat(
            "image dimensions are zero".into(),
        ));
    }

    let pad = row_padding(width) as usize;
    let row_data_bytes = (width as usize) * (BYTES_PER_PIXEL as usize);
    let expected_pixel_end = pixel_offset + (row_data_bytes + pad) * (height as usize);

    if bmp_data.len() < expected_pixel_end {
        return Err(StegoError::InvalidFormat(
            "BMP data is truncated (pixel data extends beyond EOF)".into(),
        ));
    }

    // Closure to extract the n-th LSB from pixel channel data (row-aware).
    let extract_bit = |bit_idx: usize| -> Result<u8, StegoError> {
        // Which channel byte is this in the overall pixel data (excluding padding)?
        let channel_per_row = row_data_bytes;
        let row = bit_idx / channel_per_row;
        let col = bit_idx % channel_per_row;
        if row >= height as usize {
            return Err(StegoError::ExtractionFailed(
                "bit index out of image bounds".into(),
            ));
        }
        let pos = pixel_offset + row * (row_data_bytes + pad) + col;
        Ok(bmp_data[pos] & 1)
    };

    // ----- Extract 32-bit length prefix -----
    let mut length_bytes = [0u8; 4];
    for byte_idx in 0..4usize {
        let mut byte_val = 0u8;
        for bit_pos in 0..8usize {
            let bit = extract_bit(byte_idx * 8 + bit_pos)?;
            byte_val |= bit << bit_pos;
        }
        length_bytes[byte_idx] = byte_val;
    }
    let payload_len = u32::from_le_bytes(length_bytes) as usize;

    // Validate the extracted length.
    let cap = capacity(width, height);
    if payload_len > cap {
        return Err(StegoError::PayloadTooLarge {
            capacity: cap,
            needed: payload_len,
        });
    }

    // ----- Extract payload -----
    let mut payload = Vec::with_capacity(payload_len);
    let bit_offset = LENGTH_PREFIX_BITS;
    for byte_idx in 0..payload_len {
        let mut byte_val = 0u8;
        for bit_pos in 0..8usize {
            let global_bit = bit_offset + byte_idx * 8 + bit_pos;
            let bit = extract_bit(global_bit)?;
            byte_val |= bit << bit_pos;
        }
        payload.push(byte_val);
    }

    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 64];
        rng.fill_bytes(&mut payload);

        let bmp = encode(&payload);
        let decoded = decode(&bmp).expect("decode should succeed");
        assert_eq!(decoded, payload, "roundtrip payload must match");
    }

    #[test]
    fn test_encode_decode_empty() {
        let payload: Vec<u8> = Vec::new();
        let bmp = encode(&payload);
        let decoded = decode(&bmp).expect("decode of empty payload should succeed");
        assert!(decoded.is_empty(), "decoded payload should be empty");
    }

    #[test]
    fn test_encode_decode_large() {
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 1024];
        rng.fill_bytes(&mut payload);

        let bmp = encode(&payload);
        let decoded = decode(&bmp).expect("decode of 1KB payload should succeed");
        assert_eq!(decoded, payload, "large payload roundtrip must match");
    }

    #[test]
    fn test_valid_bmp_header() {
        let payload = b"hello veilcomm";
        let bmp = encode(payload);
        assert!(bmp.len() >= 54, "BMP must contain at least the headers");
        assert_eq!(bmp[0], b'B', "first byte must be 'B'");
        assert_eq!(bmp[1], b'M', "second byte must be 'M'");

        // Verify file size field matches actual length.
        let file_size = read_u32_le(&bmp, 2) as usize;
        assert_eq!(file_size, bmp.len(), "file size header must match data length");

        // Verify pixel data offset.
        let offset = read_u32_le(&bmp, 10);
        assert_eq!(offset, HEADERS_SIZE, "pixel offset must equal combined header size");

        // Verify bits-per-pixel.
        let bpp = read_u16_le(&bmp, 28);
        assert_eq!(bpp, 24, "bits per pixel must be 24");
    }

    #[test]
    fn test_capacity() {
        // 10x10 image: 100 pixels, 300 embeddable bits, minus 32 for length = 268 bits = 33 bytes
        assert_eq!(capacity(10, 10), 33);

        // 1x1 image: 1 pixel, 3 bits total, minus 32 = 0 (saturating sub)
        assert_eq!(capacity(1, 1), 0);

        // 100x100: 10000 pixels, 30000 bits, minus 32 = 29968 bits = 3746 bytes
        assert_eq!(capacity(100, 100), 3746);

        // 0-dimension edge case.
        assert_eq!(capacity(0, 100), 0);
        assert_eq!(capacity(100, 0), 0);
    }

    #[test]
    fn test_decode_invalid() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = decode(&garbage);
        assert!(result.is_err(), "garbage input must fail");
        match result.unwrap_err() {
            StegoError::InvalidFormat(_) => {} // expected
            other => panic!("expected InvalidFormat, got: {other}"),
        }
    }

    #[test]
    fn test_decode_truncated() {
        let payload = b"test data for truncation";
        let bmp = encode(payload);

        // Truncate the BMP in the middle of the pixel data.
        let truncated = &bmp[..HEADERS_SIZE as usize + 4];
        let result = decode(truncated);
        assert!(result.is_err(), "truncated BMP must fail");
        match result.unwrap_err() {
            StegoError::InvalidFormat(msg) => {
                assert!(
                    msg.contains("truncated"),
                    "error message should mention truncation, got: {msg}"
                );
            }
            other => panic!("expected InvalidFormat for truncated BMP, got: {other}"),
        }
    }
}
