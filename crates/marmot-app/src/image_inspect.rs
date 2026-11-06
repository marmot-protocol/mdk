//! Header-level validation of untrusted still and animated images (PNG/APNG,
//! GIF, WebP, JPEG) shared by sticker assets and custom emoji. The limits are
//! White Noise's public-image limits: at most 4096 px per side, 4096x4096
//! pixels and 200 animation frames.

pub(crate) const MAX_IMAGE_DIMENSION: u32 = 4096;
pub(crate) const MAX_IMAGE_PIXELS: u64 = 4096 * 4096;
pub(crate) const MAX_IMAGE_FRAMES: u32 = 200;

/// Why an image was refused. `ExceedsLimits` is a well-formed image over a
/// dimension or frame limit, so hosts can tell "too big" from "not an image".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageRejection {
    Unsupported(&'static str),
    Malformed(&'static str),
    ExceedsLimits(&'static str),
}

impl ImageRejection {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Unsupported(reason) | Self::Malformed(reason) | Self::ExceedsLimits(reason) => {
                reason
            }
        }
    }
}

fn unsupported(reason: &'static str) -> ImageRejection {
    ImageRejection::Unsupported(reason)
}

fn malformed(reason: &'static str) -> ImageRejection {
    ImageRejection::Malformed(reason)
}

fn too_large(reason: &'static str) -> ImageRejection {
    ImageRejection::ExceedsLimits(reason)
}

/// What a header walk found: the canonical MIME type for the bytes' format,
/// the canvas size and the frame count (1 for a still image).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InspectedImage {
    pub(crate) mime: &'static str,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) frames: u32,
}

/// Identify the format from its magic bytes and enforce the shared limits.
/// Only headers and chunk/frame structure are read; pixel data is never
/// decoded, so the limits bound what a later decoder will be asked to do.
pub(crate) fn inspect_image(bytes: &[u8]) -> Result<InspectedImage, ImageRejection> {
    let inspected = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        inspect_png(bytes)?
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        inspect_gif(bytes)?
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        inspect_webp(bytes)?
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        inspect_jpeg(bytes)?
    } else {
        return Err(unsupported("unsupported image format"));
    };
    if inspected.width == 0
        || inspected.height == 0
        || inspected.width > MAX_IMAGE_DIMENSION
        || inspected.height > MAX_IMAGE_DIMENSION
        || u64::from(inspected.width) * u64::from(inspected.height) > MAX_IMAGE_PIXELS
    {
        return Err(too_large("image dimensions exceed limits"));
    }
    if inspected.frames == 0 || inspected.frames > MAX_IMAGE_FRAMES {
        return Err(too_large("animation frame count exceeds limits"));
    }
    Ok(inspected)
}

fn inspect_png(bytes: &[u8]) -> Result<InspectedImage, ImageRejection> {
    if bytes.len() < 33 || bytes.get(12..16) != Some(b"IHDR") {
        return Err(malformed("invalid PNG image"));
    }
    let width = be_u32(bytes, 16)?;
    let height = be_u32(bytes, 20)?;
    let mut offset = 8_usize;
    let mut declared_frames = None;
    let mut frame_controls = 0_u32;
    let mut saw_iend = false;
    while offset.checked_add(12).is_some_and(|end| end <= bytes.len()) {
        let length = be_u32(bytes, offset)? as usize;
        let chunk_end = offset
            .checked_add(12)
            .and_then(|base| base.checked_add(length))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("invalid PNG chunk length"))?;
        let kind = &bytes[offset + 4..offset + 8];
        if kind == b"acTL" {
            if length != 8 || declared_frames.is_some() {
                return Err(malformed("invalid APNG animation header"));
            }
            let frames = be_u32(bytes, offset + 8)?;
            if frames == 0 || frames > MAX_IMAGE_FRAMES {
                return Err(too_large("animation frame count exceeds limits"));
            }
            declared_frames = Some(frames);
        } else if kind == b"fcTL" {
            if length != 26 || declared_frames.is_none() {
                return Err(malformed("invalid APNG frame control"));
            }
            let frame_width = be_u32(bytes, offset + 12)?;
            let frame_height = be_u32(bytes, offset + 16)?;
            let frame_x = be_u32(bytes, offset + 20)?;
            let frame_y = be_u32(bytes, offset + 24)?;
            if frame_width == 0
                || frame_height == 0
                || frame_width > MAX_IMAGE_DIMENSION
                || frame_height > MAX_IMAGE_DIMENSION
                || frame_x
                    .checked_add(frame_width)
                    .is_none_or(|right| right > width)
                || frame_y
                    .checked_add(frame_height)
                    .is_none_or(|bottom| bottom > height)
            {
                return Err(malformed("APNG frame dimensions exceed canvas"));
            }
            frame_controls = frame_controls
                .checked_add(1)
                .ok_or_else(|| too_large("animation frame count exceeds limits"))?;
            if frame_controls > MAX_IMAGE_FRAMES {
                return Err(too_large("animation frame count exceeds limits"));
            }
        }
        offset = chunk_end;
        if kind == b"IEND" {
            saw_iend = true;
            break;
        }
    }
    if !saw_iend {
        return Err(malformed("PNG image is truncated"));
    }
    let frames = match declared_frames {
        Some(declared) if declared == frame_controls => declared,
        Some(_) => return Err(malformed("APNG frame count mismatch")),
        None if frame_controls == 0 => 1,
        None => return Err(malformed("invalid APNG frame control")),
    };
    Ok(InspectedImage {
        mime: if declared_frames.is_some() {
            "image/apng"
        } else {
            "image/png"
        },
        width,
        height,
        frames,
    })
}

fn inspect_gif(bytes: &[u8]) -> Result<InspectedImage, ImageRejection> {
    if bytes.len() < 14 {
        return Err(malformed("invalid GIF image"));
    }
    let width = le_u16(bytes, 6)? as u32;
    let height = le_u16(bytes, 8)? as u32;
    let packed = bytes[10];
    let mut offset = 13_usize;
    if packed & 0x80 != 0 {
        let table = 3_usize
            .checked_mul(1_usize << (usize::from(packed & 0x07) + 1))
            .ok_or_else(|| malformed("invalid GIF color table"))?;
        offset = offset
            .checked_add(table)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| malformed("truncated GIF color table"))?;
    }
    let mut frames = 0_u32;
    let mut saw_trailer = false;
    while offset < bytes.len() {
        match bytes[offset] {
            0x2c => {
                frames = frames.saturating_add(1);
                if frames > MAX_IMAGE_FRAMES {
                    return Err(too_large("animation frame count exceeds limits"));
                }
                if offset + 10 > bytes.len() {
                    return Err(malformed("truncated GIF image descriptor"));
                }
                let frame_x = u32::from(le_u16(bytes, offset + 1)?);
                let frame_y = u32::from(le_u16(bytes, offset + 3)?);
                let frame_width = u32::from(le_u16(bytes, offset + 5)?);
                let frame_height = u32::from(le_u16(bytes, offset + 7)?);
                validate_frame_rectangle(
                    width,
                    height,
                    frame_x,
                    frame_y,
                    frame_width,
                    frame_height,
                )?;
                let image_packed = bytes[offset + 9];
                offset += 10;
                if image_packed & 0x80 != 0 {
                    let table = 3_usize
                        .checked_mul(1_usize << (usize::from(image_packed & 0x07) + 1))
                        .ok_or_else(|| malformed("invalid GIF local color table"))?;
                    offset = offset
                        .checked_add(table)
                        .filter(|offset| *offset <= bytes.len())
                        .ok_or_else(|| malformed("truncated GIF local color table"))?;
                }
                if offset >= bytes.len() {
                    return Err(malformed("truncated GIF image data"));
                }
                offset += 1;
                offset = skip_gif_sub_blocks(bytes, offset)?;
            }
            0x21 => {
                if offset + 2 > bytes.len() {
                    return Err(malformed("truncated GIF extension"));
                }
                offset = skip_gif_sub_blocks(bytes, offset + 2)?;
            }
            0x3b => {
                saw_trailer = true;
                break;
            }
            _ => return Err(malformed("invalid GIF block")),
        }
    }
    if !saw_trailer || frames == 0 {
        return Err(malformed("GIF image is incomplete"));
    }
    Ok(InspectedImage {
        mime: "image/gif",
        width,
        height,
        frames,
    })
}

fn skip_gif_sub_blocks(bytes: &[u8], mut offset: usize) -> Result<usize, ImageRejection> {
    loop {
        let length = *bytes
            .get(offset)
            .ok_or_else(|| malformed("truncated GIF sub-block"))? as usize;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(length)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| malformed("truncated GIF sub-block"))?;
    }
}

fn inspect_webp(bytes: &[u8]) -> Result<InspectedImage, ImageRejection> {
    if bytes.len() < 20 {
        return Err(malformed("invalid WebP image"));
    }
    let riff_len = le_u32(bytes, 4)? as usize;
    let riff_end = riff_len
        .checked_add(8)
        .ok_or_else(|| malformed("invalid WebP size"))?;
    if riff_end != bytes.len() {
        return Err(malformed("WebP RIFF size does not match input"));
    }
    let mut offset = 12_usize;
    let mut dimensions = None;
    let mut frames = 0_u32;
    while offset.checked_add(8).is_some_and(|end| end <= riff_end) {
        let kind = &bytes[offset..offset + 4];
        let length = le_u32(bytes, offset + 4)? as usize;
        let data = offset + 8;
        let end = data
            .checked_add(length)
            .filter(|end| *end <= riff_end)
            .ok_or_else(|| malformed("invalid WebP chunk length"))?;
        match kind {
            b"VP8X" if length >= 10 => {
                record_webp_dimensions(
                    &mut dimensions,
                    le_u24(bytes, data + 4)?.saturating_add(1),
                    le_u24(bytes, data + 7)?.saturating_add(1),
                )?;
            }
            b"VP8 " | b"VP8L" => {
                let (width, height) = webp_bitstream_dimensions(kind, &bytes[data..end])?;
                record_webp_dimensions(&mut dimensions, width, height)?;
            }
            b"ANMF" => {
                if length < 16 {
                    return Err(malformed("truncated WebP animation frame"));
                }
                let (canvas_width, canvas_height) =
                    dimensions.ok_or_else(|| malformed("WebP frame precedes canvas"))?;
                let frame_x = webp_anmf_u24(bytes, data)?.saturating_mul(2);
                let frame_y = webp_anmf_u24(bytes, data + 3)?.saturating_mul(2);
                let stored_width = webp_anmf_u24(bytes, data + 6)?;
                let stored_height = webp_anmf_u24(bytes, data + 9)?;
                let frame_width = stored_width
                    .checked_add(1)
                    .ok_or_else(|| malformed("image frame dimensions exceed canvas"))?;
                let frame_height = stored_height
                    .checked_add(1)
                    .ok_or_else(|| malformed("image frame dimensions exceed canvas"))?;
                validate_frame_rectangle(
                    canvas_width,
                    canvas_height,
                    frame_x,
                    frame_y,
                    frame_width,
                    frame_height,
                )?;
                validate_webp_frame(&bytes[data + 16..end], frame_width, frame_height)?;
                frames = frames
                    .checked_add(1)
                    .ok_or_else(|| too_large("animation frame count exceeds limits"))?;
                if frames > MAX_IMAGE_FRAMES {
                    return Err(too_large("animation frame count exceeds limits"));
                }
            }
            _ => {}
        }
        offset = end + (length & 1);
    }
    let (width, height) = dimensions.ok_or_else(|| malformed("WebP dimensions missing"))?;
    Ok(InspectedImage {
        mime: "image/webp",
        width,
        height,
        frames: frames.max(1),
    })
}

fn webp_bitstream_dimensions(kind: &[u8], bytes: &[u8]) -> Result<(u32, u32), ImageRejection> {
    match kind {
        b"VP8L" if bytes.len() >= 5 && bytes[0] == 0x2f => {
            let bits = le_u32(bytes, 1)?;
            Ok(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
        }
        b"VP8 "
            if bytes.len() >= 10
                && bytes[0] & 1 == 0
                && bytes.get(3..6) == Some(b"\x9d\x01\x2a") =>
        {
            Ok((
                u32::from(le_u16(bytes, 6)? & 0x3fff),
                u32::from(le_u16(bytes, 8)? & 0x3fff),
            ))
        }
        _ => Err(malformed("invalid WebP bitstream header")),
    }
}

fn validate_webp_frame(bytes: &[u8], width: u32, height: u32) -> Result<(), ImageRejection> {
    let mut offset = 0_usize;
    let mut saw_image = false;
    while offset < bytes.len() {
        let data = offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("truncated WebP frame chunk"))?;
        let kind = &bytes[offset..offset + 4];
        let length = le_u32(bytes, offset + 4)? as usize;
        let end = data
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("invalid WebP frame chunk length"))?;
        if matches!(kind, b"VP8 " | b"VP8L") {
            let dimensions = webp_bitstream_dimensions(kind, &bytes[data..end])?;
            if saw_image || dimensions != (width, height) {
                return Err(malformed("WebP bitstream dimensions do not match frame"));
            }
            saw_image = true;
        }
        offset = end
            .checked_add(length & 1)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("truncated WebP frame chunk padding"))?;
    }
    if !saw_image {
        return Err(malformed("WebP frame image missing"));
    }
    Ok(())
}

fn record_webp_dimensions(
    dimensions: &mut Option<(u32, u32)>,
    width: u32,
    height: u32,
) -> Result<(), ImageRejection> {
    let next = (width, height);
    if dimensions.is_some_and(|current| current != next) {
        return Err(malformed("conflicting WebP dimensions"));
    }
    *dimensions = Some(next);
    Ok(())
}

fn validate_frame_rectangle(
    canvas_width: u32,
    canvas_height: u32,
    frame_x: u32,
    frame_y: u32,
    frame_width: u32,
    frame_height: u32,
) -> Result<(), ImageRejection> {
    if frame_width == 0
        || frame_height == 0
        || frame_width > MAX_IMAGE_DIMENSION
        || frame_height > MAX_IMAGE_DIMENSION
        || u64::from(frame_width).saturating_mul(u64::from(frame_height)) > MAX_IMAGE_PIXELS
        || frame_x
            .checked_add(frame_width)
            .is_none_or(|right| right > canvas_width)
        || frame_y
            .checked_add(frame_height)
            .is_none_or(|bottom| bottom > canvas_height)
    {
        return Err(malformed("image frame dimensions exceed canvas"));
    }
    Ok(())
}

fn webp_anmf_u24(bytes: &[u8], offset: usize) -> Result<u32, ImageRejection> {
    let bytes = bytes
        .get(offset..offset + 3)
        .ok_or_else(|| malformed("truncated WebP animation frame"))?;
    Ok(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, ImageRejection> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| malformed("truncated image header"))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, ImageRejection> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| malformed("truncated image header"))
}

fn le_u24(bytes: &[u8], offset: usize) -> Result<u32, ImageRejection> {
    let bytes = bytes
        .get(offset..offset + 3)
        .ok_or_else(|| malformed("truncated image header"))?;
    Ok(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, ImageRejection> {
    bytes
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| malformed("truncated image header"))
}

/// Walk JPEG marker segments to the first start-of-frame and read its size.
/// A JPEG is always one frame. Entropy-coded data is never read: a frame
/// header must come before the first scan.
fn inspect_jpeg(bytes: &[u8]) -> Result<InspectedImage, ImageRejection> {
    let mut offset = 2_usize;
    loop {
        if bytes.get(offset) != Some(&0xff) {
            return Err(malformed("invalid JPEG marker"));
        }
        while bytes.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let marker = *bytes
            .get(offset)
            .ok_or_else(|| malformed("JPEG image is truncated"))?;
        offset += 1;
        match marker {
            // Standalone markers carry no length.
            0x01 | 0xd0..=0xd7 => continue,
            // A second SOI, the end of the image or a scan before any frame.
            0x00 | 0xd8 | 0xd9 | 0xda => return Err(malformed("JPEG frame header missing")),
            _ => {}
        }
        let length = usize::from(be_u16(bytes, offset)?);
        let end = offset
            .checked_add(length)
            .filter(|end| length >= 2 && *end <= bytes.len())
            .ok_or_else(|| malformed("invalid JPEG segment length"))?;
        // SOF0..SOF15, except DHT (C4), JPG (C8) and DAC (CC).
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            if length < 8 {
                return Err(malformed("invalid JPEG frame header"));
            }
            return Ok(InspectedImage {
                mime: "image/jpeg",
                width: u32::from(be_u16(bytes, offset + 5)?),
                height: u32::from(be_u16(bytes, offset + 3)?),
                frames: 1,
            });
        }
        offset = end;
    }
}

fn be_u16(bytes: &[u8], offset: usize) -> Result<u16, ImageRejection> {
    bytes
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| malformed("truncated image header"))
}

#[cfg(test)]
pub(crate) mod test_images {
    pub(crate) fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }

    pub(crate) fn png_with_frames(
        width: u32,
        height: u32,
        declared_frames: Option<u32>,
        frames: &[(u32, u32, u32, u32)],
    ) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes.extend(chunk(b"IHDR", &ihdr));
        if let Some(frames) = declared_frames {
            let mut actl = Vec::new();
            actl.extend_from_slice(&frames.to_be_bytes());
            actl.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend(chunk(b"acTL", &actl));
        }
        for (sequence, (frame_width, frame_height, frame_x, frame_y)) in frames.iter().enumerate() {
            let mut frame_control = Vec::with_capacity(26);
            frame_control.extend_from_slice(&(sequence as u32).to_be_bytes());
            frame_control.extend_from_slice(&frame_width.to_be_bytes());
            frame_control.extend_from_slice(&frame_height.to_be_bytes());
            frame_control.extend_from_slice(&frame_x.to_be_bytes());
            frame_control.extend_from_slice(&frame_y.to_be_bytes());
            frame_control.extend_from_slice(&[0; 6]);
            bytes.extend(chunk(b"fcTL", &frame_control));
        }
        bytes.extend(chunk(b"IEND", &[]));
        bytes
    }

    pub(crate) fn png(width: u32, height: u32, animation_frames: Option<u32>) -> Vec<u8> {
        let frames = vec![(width, height, 0, 0); animation_frames.unwrap_or_default() as usize];
        png_with_frames(width, height, animation_frames, &frames)
    }

    pub(crate) fn gif_with_frame(
        width: u16,
        height: u16,
        frame_x: u16,
        frame_y: u16,
        frame_width: u16,
        frame_height: u16,
    ) -> Vec<u8> {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&width.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.push(0x2c);
        bytes.extend_from_slice(&frame_x.to_le_bytes());
        bytes.extend_from_slice(&frame_y.to_le_bytes());
        bytes.extend_from_slice(&frame_width.to_le_bytes());
        bytes.extend_from_slice(&frame_height.to_le_bytes());
        bytes.extend_from_slice(&[0, 2, 0, 0x3b]);
        bytes
    }

    pub(crate) fn webp_with_frame(
        width: u32,
        height: u32,
        frame_x: u32,
        frame_y: u32,
        frame_width: u32,
        frame_height: u32,
    ) -> Vec<u8> {
        let mut vp8x = vec![0x02, 0, 0, 0];
        vp8x.extend_from_slice(&(width.saturating_sub(1) & 0xff_ffff).to_le_bytes()[..3]);
        vp8x.extend_from_slice(&(height.saturating_sub(1) & 0xff_ffff).to_le_bytes()[..3]);
        let mut anmf = Vec::new();
        anmf.extend_from_slice(&(frame_x / 2).to_le_bytes()[..3]);
        anmf.extend_from_slice(&(frame_y / 2).to_le_bytes()[..3]);
        let stored_width = frame_width.checked_sub(1).unwrap_or(0xff_ffff);
        let stored_height = frame_height.checked_sub(1).unwrap_or(0xff_ffff);
        anmf.extend_from_slice(&(stored_width & 0xff_ffff).to_le_bytes()[..3]);
        anmf.extend_from_slice(&(stored_height & 0xff_ffff).to_le_bytes()[..3]);
        anmf.extend_from_slice(&[0; 4]);
        anmf.extend_from_slice(b"VP8L\x05\x00\x00\x00\x2f");
        let image_dimensions = (stored_width & 0x3fff) | ((stored_height & 0x3fff) << 14);
        anmf.extend_from_slice(&image_dimensions.to_le_bytes());
        anmf.push(0);
        let mut payload = Vec::new();
        payload.extend_from_slice(b"VP8X");
        payload.extend_from_slice(&(vp8x.len() as u32).to_le_bytes());
        payload.extend(vp8x);
        if anmf.len() % 2 == 1 {
            anmf.push(0);
        }
        payload.extend_from_slice(b"ANMF");
        payload.extend_from_slice(&(anmf.len() as u32).to_le_bytes());
        payload.extend(anmf);
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&(payload.len() as u32 + 4).to_le_bytes());
        bytes.extend_from_slice(b"WEBP");
        bytes.extend(payload);
        bytes
    }

    /// A minimal baseline JPEG header: SOI, an APP0 segment, SOF0 and EOI.
    pub(crate) fn jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = vec![0xff, 0xd8];
        bytes.extend_from_slice(&[0xff, 0xe0, 0x00, 0x10]);
        bytes.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        bytes.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[0x03, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        bytes.extend_from_slice(&[0xff, 0xd9]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::test_images::*;
    use super::*;

    #[test]
    fn image_inspection_enforces_dimensions_and_animation_limits() {
        assert_eq!(
            inspect_image(&png(512, 256, None)).unwrap(),
            InspectedImage {
                mime: "image/png",
                width: 512,
                height: 256,
                frames: 1,
            }
        );
        assert_eq!(
            inspect_image(&png(32, 48, Some(2))).unwrap().mime,
            "image/apng"
        );
        assert!(inspect_image(&png(4097, 1, None)).is_err());
        assert!(inspect_image(&png(32, 32, Some(MAX_IMAGE_FRAMES + 1))).is_err());
        assert!(
            inspect_image(&png_with_frames(
                32,
                32,
                Some(1),
                &[(32, 32, 0, 0), (32, 32, 0, 0)],
            ))
            .is_err()
        );
        assert!(
            inspect_image(&png_with_frames(
                32,
                32,
                Some(1),
                &vec![(32, 32, 0, 0); MAX_IMAGE_FRAMES as usize + 1],
            ))
            .is_err()
        );
        assert!(inspect_image(&png_with_frames(32, 32, Some(1), &[(0, 32, 0, 0)])).is_err());
        assert!(inspect_image(&png_with_frames(32, 32, Some(1), &[(33, 32, 0, 0)])).is_err());
        assert!(inspect_image(&png_with_frames(32, 32, Some(1), &[(16, 16, 17, 0)])).is_err());
        // In-canvas frames inspect cleanly, so the rejections below are not
        // an always-failing frame check.
        let gif = inspect_image(&gif_with_frame(32, 32, 8, 8, 16, 16)).unwrap();
        assert_eq!((gif.width, gif.height, gif.frames), (32, 32, 1));
        assert_eq!(gif.mime, "image/gif");
        let webp = inspect_image(&webp_with_frame(32, 32, 0, 0, 16, 16)).unwrap();
        assert_eq!((webp.width, webp.height, webp.frames), (32, 32, 1));
        assert_eq!(webp.mime, "image/webp");
        assert!(inspect_image(&gif_with_frame(32, 32, 0, 0, 0, 32)).is_err());
        assert!(inspect_image(&gif_with_frame(32, 32, 0, 0, 33, 32)).is_err());
        assert!(inspect_image(&gif_with_frame(32, 32, 17, 0, 16, 16)).is_err());
        assert!(inspect_image(&webp_with_frame(32, 32, 0, 0, 0, 32)).is_err());
        assert!(inspect_image(&webp_with_frame(32, 32, 0, 0, 33, 32)).is_err());
        assert!(inspect_image(&webp_with_frame(32, 32, 18, 0, 16, 16)).is_err());
        let mut trailing = webp_with_frame(32, 32, 0, 0, 16, 16);
        trailing.extend_from_slice(b"VP8L   /     ");
        assert!(inspect_image(&trailing).is_err());
        let mut conflicting = webp_with_frame(32, 32, 0, 0, 16, 16);
        conflicting.extend_from_slice(b"VP8L\x05\x00\x00\x00/\x00\x00\x00\x00\x00");
        let riff_len = u32::try_from(conflicting.len() - 8).unwrap();
        conflicting[4..8].copy_from_slice(&riff_len.to_le_bytes());
        assert!(inspect_image(&conflicting).is_err());
        assert!(inspect_image(b"not an image").is_err());
    }

    #[test]
    fn webp_frames_check_bitstreams() {
        let replace_image = |image: &[u8]| {
            let mut bytes = webp_with_frame(32, 32, 0, 0, 16, 16);
            let frame = bytes.windows(4).position(|bytes| bytes == b"ANMF").unwrap();
            bytes.truncate(frame + 8 + 16);
            bytes.extend_from_slice(image);
            let frame_len = u32::try_from(16 + image.len()).unwrap();
            bytes[frame + 4..frame + 8].copy_from_slice(&frame_len.to_le_bytes());
            let riff_len = u32::try_from(bytes.len() - 8).unwrap();
            bytes[4..8].copy_from_slice(&riff_len.to_le_bytes());
            bytes
        };
        for kind in [b"VP8 ", b"VP8L"] {
            for (width, height) in [(16_u16, 16_u16), (17, 16), (16, 17), (16383, 16383)] {
                let mut image = kind.to_vec();
                if kind == b"VP8 " {
                    image.extend_from_slice(&10_u32.to_le_bytes());
                    image.extend_from_slice(b"\x10\x00\x00\x9d\x01\x2a");
                    image.extend_from_slice(&width.to_le_bytes());
                    image.extend_from_slice(&height.to_le_bytes());
                } else {
                    image.extend_from_slice(&5_u32.to_le_bytes());
                    image.push(0x2f);
                    let bits = u32::from(width - 1) | (u32::from(height - 1) << 14);
                    image.extend_from_slice(&bits.to_le_bytes());
                    image.push(0);
                }
                let bytes = replace_image(&image);
                assert_eq!(inspect_image(&bytes).is_ok(), (width, height) == (16, 16));
            }
        }
        for image in [
            &b""[..],
            &b"VP8 "[..],
            &b"VP8L\x05\x00\x00\x00\x2f\x0f\xc0\x03"[..],
            &b"VP8L\x05\x00\x00\x00\x2f\x0f\xc0\x03\x00"[..],
        ] {
            assert!(inspect_image(&replace_image(image)).is_err());
        }
    }

    #[test]
    fn jpeg_reads_its_frame_header_and_rejects_hostile_layouts() {
        assert_eq!(
            inspect_image(&jpeg(640, 480)).unwrap(),
            InspectedImage {
                mime: "image/jpeg",
                width: 640,
                height: 480,
                frames: 1,
            }
        );
        assert!(matches!(
            inspect_image(&jpeg(4097, 16)),
            Err(ImageRejection::ExceedsLimits(_))
        ));
        assert!(matches!(
            inspect_image(&jpeg(0, 16)),
            Err(ImageRejection::ExceedsLimits(_))
        ));
        // A scan before any frame header, a truncated segment and a segment
        // length that overruns the buffer are malformed, not unsupported.
        let mut scan_first = vec![0xff, 0xd8, 0xff, 0xda, 0x00, 0x02];
        scan_first.extend(jpeg(16, 16).split_off(2));
        assert!(matches!(
            inspect_image(&scan_first),
            Err(ImageRejection::Malformed(_))
        ));
        let full = jpeg(16, 16);
        assert!(matches!(
            inspect_image(&full[..10]),
            Err(ImageRejection::Malformed(_))
        ));
        let mut overrun = full.clone();
        overrun[4..6].copy_from_slice(&0xfff0_u16.to_be_bytes());
        assert!(matches!(
            inspect_image(&overrun),
            Err(ImageRejection::Malformed(_))
        ));
        assert!(matches!(
            inspect_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
            Err(ImageRejection::Unsupported(_))
        ));
    }
}
