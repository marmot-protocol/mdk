use std::io::Cursor;

use image::{AnimationDecoder, ImageDecoder, ImageFormat, ImageReader, Limits};
use zeroize::Zeroizing;

use crate::AppError;

pub(crate) const MAX_VIEW_ONCE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const VIEW_ONCE_MIME: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "video/mp4",
];
const MAX_DIMENSION: u32 = 8192;
const MAX_PIXELS: u64 = 16_777_216;
const MAX_ANIMATION_FRAMES: usize = 256;
const MAX_ANIMATION_PIXELS: u64 = 67_108_864;
const MAX_MP4_SAMPLES: usize = 262_144;

fn invalid(reason: &'static str) -> AppError {
    AppError::InvalidEncryptedMedia(reason.into())
}

pub(crate) fn validate_view_once_media_type(media_type: &str) -> Result<(), AppError> {
    if VIEW_ONCE_MIME.contains(&media_type) {
        Ok(())
    } else {
        Err(invalid("view-once media type is not supported"))
    }
}

pub(crate) fn validate_view_once_content(bytes: &[u8], media_type: &str) -> Result<(), AppError> {
    validate_view_once_media_type(media_type)?;
    if bytes.is_empty() || bytes.len() > MAX_VIEW_ONCE_BYTES {
        return Err(invalid("view-once media exceeds its size limit"));
    }
    if media_type == "video/mp4" {
        return validate_mp4(bytes);
    }
    let expected = match media_type {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/gif" => ImageFormat::Gif,
        "image/webp" => ImageFormat::WebP,
        _ => return Err(invalid("view-once media type is not supported")),
    };
    if image::guess_format(bytes).ok() != Some(expected) {
        return Err(invalid("view-once media type does not match its bytes"));
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), expected);
    reader.limits(image_limits());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| invalid("view-once image is invalid"))?;
    dimensions(width, height)?;
    match expected {
        ImageFormat::Gif => {
            let mut decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes))
                .map_err(|_| invalid("view-once image is invalid"))?;
            decoder
                .set_limits(image_limits())
                .map_err(|_| invalid("view-once image exceeds decode limits"))?;
            decode_frames(decoder.into_frames())
        }
        ImageFormat::Png => {
            let decoder =
                image::codecs::png::PngDecoder::with_limits(Cursor::new(bytes), image_limits())
                    .map_err(|_| invalid("view-once image is invalid"))?;
            if decoder
                .is_apng()
                .map_err(|_| invalid("view-once image is invalid"))?
            {
                decode_frames(
                    decoder
                        .apng()
                        .map_err(|_| invalid("view-once image is invalid"))?
                        .into_frames(),
                )
            } else {
                decode_image(decoder)
            }
        }
        ImageFormat::WebP => {
            let mut decoder = image::codecs::webp::WebPDecoder::new(Cursor::new(bytes))
                .map_err(|_| invalid("view-once image is invalid"))?;
            decoder
                .set_limits(image_limits())
                .map_err(|_| invalid("view-once image exceeds decode limits"))?;
            if decoder.has_animation() {
                decode_frames(decoder.into_frames())
            } else {
                decode_image(decoder)
            }
        }
        ImageFormat::Jpeg => {
            let mut reader = ImageReader::with_format(Cursor::new(bytes), expected);
            reader.limits(image_limits());
            decode_image(
                reader
                    .into_decoder()
                    .map_err(|_| invalid("view-once image is invalid"))?,
            )
        }
        _ => Err(invalid("view-once image format is not supported")),
    }
}

fn image_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_VIEW_ONCE_BYTES as u64);
    limits
}

fn dimensions(width: u32, height: u32) -> Result<(), AppError> {
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err(invalid("view-once media dimensions exceed limits"));
    }
    Ok(())
}

fn decode_image(decoder: impl ImageDecoder) -> Result<(), AppError> {
    let (width, height) = decoder.dimensions();
    dimensions(width, height)?;
    let len = usize::try_from(decoder.total_bytes())
        .map_err(|_| invalid("view-once image exceeds decode limits"))?;
    if len > MAX_VIEW_ONCE_BYTES {
        return Err(invalid("view-once image exceeds decode limits"));
    }
    let mut decoded = Zeroizing::new(vec![0; len]);
    decoder
        .read_image(&mut decoded)
        .map_err(|_| invalid("view-once image cannot be fully decoded"))
}

fn decode_frames(frames: image::Frames<'_>) -> Result<(), AppError> {
    let mut total = 0_u64;
    let mut count = 0;
    for frame in frames {
        count += 1;
        let frame = frame.map_err(|_| invalid("view-once image cannot be fully decoded"))?;
        let buffer = frame.into_buffer();
        let (width, height) = buffer.dimensions();
        let _decoded = Zeroizing::new(buffer.into_raw());
        if count > MAX_ANIMATION_FRAMES {
            return Err(invalid("view-once animation exceeds frame limit"));
        }
        dimensions(width, height)?;
        total += u64::from(width) * u64::from(height);
        if total > MAX_ANIMATION_PIXELS {
            return Err(invalid("view-once animation exceeds decode limits"));
        }
    }
    if count == 0 {
        return Err(invalid("view-once animation has no frames"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Mp4Box<'a> {
    kind: [u8; 4],
    body: &'a [u8],
    start: usize,
}

fn boxes(bytes: &[u8], base: usize) -> Result<Vec<Mp4Box<'_>>, AppError> {
    let mut result = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if result.len() >= 4096 || bytes.len() - offset < 8 {
            return Err(invalid("view-once MP4 has invalid boxes"));
        }
        let size = u32_at(bytes, offset)?;
        let kind = bytes[offset + 4..offset + 8]
            .try_into()
            .map_err(|_| invalid("view-once MP4 has invalid boxes"))?;
        let (size, header) = match size {
            0 => (bytes.len() - offset, 8),
            1 => (
                usize::try_from(u64_at(bytes, offset + 8)?)
                    .map_err(|_| invalid("view-once MP4 box is too large"))?,
                16,
            ),
            value => (value as usize, 8),
        };
        let end = offset
            .checked_add(size)
            .filter(|end| size >= header && *end <= bytes.len())
            .ok_or_else(|| invalid("view-once MP4 has truncated boxes"))?;
        result.push(Mp4Box {
            kind,
            body: &bytes[offset + header..end],
            start: base + offset + header,
        });
        offset = end;
    }
    Ok(result)
}

fn one<'a>(items: &[Mp4Box<'a>], kind: &[u8; 4]) -> Result<Mp4Box<'a>, AppError> {
    optional(items, kind)?.ok_or_else(|| invalid("view-once MP4 is missing required boxes"))
}

fn optional<'a>(items: &[Mp4Box<'a>], kind: &[u8; 4]) -> Result<Option<Mp4Box<'a>>, AppError> {
    let mut matching = items.iter().filter(|item| &item.kind == kind);
    let item = matching.next().copied();
    if matching.next().is_some() {
        return Err(invalid("view-once MP4 has duplicate boxes"));
    }
    Ok(item)
}

fn children(item: Mp4Box<'_>) -> Result<Vec<Mp4Box<'_>>, AppError> {
    boxes(item.body, item.start)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, AppError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("view-once MP4 is truncated"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, AppError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("view-once MP4 is truncated"))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, AppError> {
    Ok((u64::from(u32_at(bytes, offset)?) << 32) | u64::from(u32_at(bytes, offset + 4)?))
}

fn full_box(bytes: &[u8]) -> Result<(), AppError> {
    if bytes.get(..4) != Some(&[0, 0, 0, 0]) {
        return Err(invalid(
            "view-once MP4 has unsupported box version or flags",
        ));
    }
    Ok(())
}

fn validate_mp4(bytes: &[u8]) -> Result<(), AppError> {
    let top = boxes(bytes, 0)?;
    let ftyp = one(&top, b"ftyp")?;
    if ftyp.body.len() < 8
        || ftyp.body.len() % 4 != 0
        || !ftyp.body.chunks_exact(4).enumerate().any(|(index, brand)| {
            index != 1 && matches!(brand, b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1")
        })
    {
        return Err(invalid("view-once MP4 has unsupported file type"));
    }
    if top
        .iter()
        .any(|item| matches!(&item.kind, b"moof" | b"mfra"))
    {
        return Err(invalid("view-once fragmented MP4 is not supported"));
    }
    let moov = children(one(&top, b"moov")?)?;
    if moov.iter().any(|item| &item.kind == b"mvex") {
        return Err(invalid("view-once fragmented MP4 is not supported"));
    }
    let mvhd = one(&moov, b"mvhd")?;
    let version = *mvhd
        .body
        .first()
        .ok_or_else(|| invalid("view-once MP4 is truncated"))?;
    let timescale_offset = match version {
        0 => 12,
        1 => 20,
        _ => return Err(invalid("view-once MP4 has invalid movie header")),
    };
    if u32_at(mvhd.body, timescale_offset)? == 0 {
        return Err(invalid("view-once MP4 has invalid movie timescale"));
    }
    if !top
        .iter()
        .any(|item| &item.kind == b"mdat" && !item.body.is_empty())
    {
        return Err(invalid("view-once MP4 has no media data"));
    }
    let tracks = moov.iter().filter(|item| &item.kind == b"trak");
    if !(1..=2).contains(&tracks.clone().count()) {
        return Err(invalid("view-once MP4 has invalid track count"));
    }
    let mut video = false;
    for track in tracks {
        let is_video = validate_track(*track, bytes, &top)?;
        if is_video && video {
            return Err(invalid("view-once MP4 has multiple video tracks"));
        }
        video |= is_video;
    }
    if !video {
        return Err(invalid("view-once MP4 has no supported video track"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TrackKind {
    Video,
    Audio,
}

struct SampleCodec {
    kind: TrackKind,
    nal_length: usize,
    pps_ids: [u64; 4],
    macroblocks: u32,
}

fn validate_track(track: Mp4Box<'_>, bytes: &[u8], mdats: &[Mp4Box<'_>]) -> Result<bool, AppError> {
    let track = children(track)?;
    let tkhd = one(&track, b"tkhd")?;
    let tkhd_len = match tkhd.body.first() {
        Some(0) => 84,
        Some(1) => 96,
        _ => return Err(invalid("view-once MP4 has invalid track header")),
    };
    if tkhd.body.len() != tkhd_len {
        return Err(invalid("view-once MP4 has invalid track header"));
    }
    let mdia = children(one(&track, b"mdia")?)?;
    let mdhd = one(&mdia, b"mdhd")?;
    let time_offset = match mdhd.body.first() {
        Some(0) => 12,
        Some(1) => 20,
        _ => return Err(invalid("view-once MP4 has invalid media header")),
    };
    if u32_at(mdhd.body, time_offset)? == 0 {
        return Err(invalid("view-once MP4 has invalid media timescale"));
    }
    let hdlr = one(&mdia, b"hdlr")?;
    let handler = hdlr
        .body
        .get(8..12)
        .ok_or_else(|| invalid("view-once MP4 has invalid media handler"))?;
    let kind = match handler {
        b"vide" => TrackKind::Video,
        b"soun" => TrackKind::Audio,
        _ => return Err(invalid("view-once MP4 track type is not supported")),
    };
    if matches!(kind, TrackKind::Video) {
        let width = u32_at(tkhd.body, tkhd_len - 8)?;
        let height = u32_at(tkhd.body, tkhd_len - 4)?;
        dimensions(width.div_ceil(65536), height.div_ceil(65536))?;
    }
    let minf = children(one(&mdia, b"minf")?)?;
    let dinf = children(one(&minf, b"dinf")?)?;
    let dref = one(&dinf, b"dref")?;
    full_box(dref.body)?;
    if u32_at(dref.body, 4)? != 1 {
        return Err(invalid("view-once MP4 has external data references"));
    }
    let refs = boxes(
        dref.body
            .get(8..)
            .ok_or_else(|| invalid("view-once MP4 is truncated"))?,
        dref.start + 8,
    )?;
    let url = one(&refs, b"url ")?;
    if refs.len() != 1 || url.body != [0, 0, 0, 1] {
        return Err(invalid("view-once MP4 has external data references"));
    }
    let stbl = children(one(&minf, b"stbl")?)?;
    let stsd = one(&stbl, b"stsd")?;
    full_box(stsd.body)?;
    if u32_at(stsd.body, 4)? != 1 {
        return Err(invalid("view-once MP4 has unsupported sample descriptions"));
    }
    let descriptions = boxes(
        stsd.body
            .get(8..)
            .ok_or_else(|| invalid("view-once MP4 is truncated"))?,
        stsd.start + 8,
    )?;
    if descriptions.len() != 1 {
        return Err(invalid("view-once MP4 has unsupported sample descriptions"));
    }
    let codec = validate_sample_description(descriptions[0], kind)?;
    validate_samples(&stbl, bytes, mdats, &codec)?;
    Ok(matches!(kind, TrackKind::Video))
}

fn validate_sample_description(
    entry: Mp4Box<'_>,
    kind: TrackKind,
) -> Result<SampleCodec, AppError> {
    if u16_at(entry.body, 6)? != 1 {
        return Err(invalid("view-once MP4 has external sample data"));
    }
    if matches!(kind, TrackKind::Video) {
        if &entry.kind != b"avc1" || entry.body.len() < 78 {
            return Err(invalid("view-once MP4 video codec is not supported"));
        }
        let width = u32::from(u16_at(entry.body, 24)?);
        let height = u32::from(u16_at(entry.body, 26)?);
        dimensions(width, height)?;
        let config = boxes(&entry.body[78..], entry.start + 78)?;
        let avcc = one(&config, b"avcC")?;
        let (nal_length, pps_ids) = validate_avcc(avcc.body, width, height)?;
        Ok(SampleCodec {
            kind,
            nal_length,
            pps_ids,
            macroblocks: width.div_ceil(16) * height.div_ceil(16),
        })
    } else {
        if &entry.kind != b"mp4a"
            || entry.body.len() < 28
            || u16_at(entry.body, 8)? != 0
            || !(1..=2).contains(&u16_at(entry.body, 16)?)
            || u32_at(entry.body, 24)? >> 16 > 96_000
        {
            return Err(invalid("view-once MP4 audio codec is not supported"));
        }
        let config = boxes(&entry.body[28..], entry.start + 28)?;
        validate_aac(one(&config, b"esds")?.body)?;
        Ok(SampleCodec {
            kind,
            nal_length: 0,
            pps_ids: [0; 4],
            macroblocks: 0,
        })
    }
}

fn counted_table(bytes: &[u8], header: usize, stride: usize) -> Result<usize, AppError> {
    full_box(bytes)?;
    let count = u32_at(bytes, header - 4)? as usize;
    if count == 0 || count > MAX_MP4_SAMPLES || bytes.len() != header + count * stride {
        return Err(invalid("view-once MP4 has invalid sample tables"));
    }
    Ok(count)
}

fn validate_samples(
    stbl: &[Mp4Box<'_>],
    bytes: &[u8],
    mdats: &[Mp4Box<'_>],
    codec: &SampleCodec,
) -> Result<(), AppError> {
    let stsz = one(stbl, b"stsz")?;
    full_box(stsz.body)?;
    let fixed = u32_at(stsz.body, 4)? as usize;
    let count = u32_at(stsz.body, 8)? as usize;
    if count == 0
        || count > MAX_MP4_SAMPLES
        || stsz.body.len() != 12 + if fixed == 0 { count * 4 } else { 0 }
    {
        return Err(invalid("view-once MP4 has invalid sample sizes"));
    }
    let stts = one(stbl, b"stts")?;
    let timing_count = counted_table(stts.body, 8, 8)?;
    let mut timed_samples = 0_u64;
    for index in 0..timing_count {
        let n = u32_at(stts.body, 8 + index * 8)?;
        if n == 0 || u32_at(stts.body, 12 + index * 8)? == 0 {
            return Err(invalid("view-once MP4 has invalid sample timing"));
        }
        timed_samples += u64::from(n);
    }
    if timed_samples != count as u64 {
        return Err(invalid("view-once MP4 sample counts disagree"));
    }
    if let Some(ctts) = optional(stbl, b"ctts")? {
        if !matches!(ctts.body.first(), Some(0 | 1)) || ctts.body.get(1..4) != Some(&[0, 0, 0]) {
            return Err(invalid("view-once MP4 has invalid composition timing"));
        }
        let entries = u32_at(ctts.body, 4)? as usize;
        if entries > MAX_MP4_SAMPLES || ctts.body.len() != 8 + entries * 8 {
            return Err(invalid("view-once MP4 has invalid composition timing"));
        }
        let mut total = 0_u64;
        for index in 0..entries {
            total += u64::from(u32_at(ctts.body, 8 + index * 8)?);
        }
        if total != count as u64 {
            return Err(invalid("view-once MP4 sample counts disagree"));
        }
    }
    if let Some(stss) = optional(stbl, b"stss")? {
        let entries = counted_table(stss.body, 8, 4)?;
        let mut previous = 0;
        for index in 0..entries {
            let sample = u32_at(stss.body, 8 + index * 4)? as usize;
            if sample <= previous || sample > count {
                return Err(invalid("view-once MP4 has invalid sync samples"));
            }
            previous = sample;
        }
    }
    let offsets = match (optional(stbl, b"stco")?, optional(stbl, b"co64")?) {
        (Some(offsets), None) | (None, Some(offsets)) => offsets,
        _ => return Err(invalid("view-once MP4 has invalid chunk offsets")),
    };
    let stride = if &offsets.kind == b"co64" { 8 } else { 4 };
    let chunks = counted_table(offsets.body, 8, stride)?;
    let stsc = one(stbl, b"stsc")?;
    let runs = counted_table(stsc.body, 8, 12)?;
    let mut previous = 0;
    for index in 0..runs {
        let first = u32_at(stsc.body, 8 + index * 12)? as usize;
        if first <= previous
            || first > chunks
            || (index == 0 && first != 1)
            || u32_at(stsc.body, 12 + index * 12)? == 0
            || u32_at(stsc.body, 16 + index * 12)? != 1
        {
            return Err(invalid("view-once MP4 has invalid sample chunks"));
        }
        previous = first;
    }
    let mut sample = 0;
    let mut run = 0;
    let mut previous_end = 0_usize;
    for chunk in 0..chunks {
        if run + 1 < runs && u32_at(stsc.body, 8 + (run + 1) * 12)? as usize == chunk + 1 {
            run += 1;
        }
        let per_chunk = u32_at(stsc.body, 12 + run * 12)? as usize;
        let offset = if stride == 8 {
            u64_at(offsets.body, 8 + chunk * 8)?
        } else {
            u64::from(u32_at(offsets.body, 8 + chunk * 4)?)
        };
        let mut offset = usize::try_from(offset)
            .map_err(|_| invalid("view-once MP4 chunk offset is too large"))?;
        if offset < previous_end || per_chunk > count - sample {
            return Err(invalid("view-once MP4 has overlapping or invalid samples"));
        }
        for _ in 0..per_chunk {
            let size = if fixed != 0 {
                fixed
            } else {
                u32_at(stsz.body, 12 + sample * 4)? as usize
            };
            let end = offset
                .checked_add(size)
                .filter(|end| size > 0 && *end <= bytes.len())
                .ok_or_else(|| invalid("view-once MP4 sample is truncated"))?;
            if !mdats.iter().any(|mdat| {
                &mdat.kind == b"mdat" && offset >= mdat.start && end <= mdat.start + mdat.body.len()
            }) {
                return Err(invalid("view-once MP4 sample points outside media data"));
            }
            if matches!(codec.kind, TrackKind::Video) {
                validate_avc_sample(&bytes[offset..end], codec)?;
            }
            offset = end;
            sample += 1;
        }
        previous_end = offset;
    }
    if sample != count {
        return Err(invalid("view-once MP4 sample counts disagree"));
    }
    Ok(())
}

fn validate_avc_sample(mut bytes: &[u8], codec: &SampleCodec) -> Result<(), AppError> {
    let length_size = codec.nal_length;
    let mut slice = false;
    while !bytes.is_empty() {
        let length_bytes = bytes
            .get(..length_size)
            .ok_or_else(|| invalid("view-once AVC sample is truncated"))?;
        let len = length_bytes
            .iter()
            .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
        bytes = &bytes[length_size..];
        let nal = bytes
            .get(..len)
            .filter(|nal| !nal.is_empty())
            .ok_or_else(|| invalid("view-once AVC NAL is truncated"))?;
        let kind = nal[0] & 31;
        if nal[0] & 0x80 != 0 || !matches!(kind, 1 | 5 | 6 | 9 | 12) || nal.len() < 2 {
            return Err(invalid("view-once AVC sample has unsupported NAL content"));
        }
        if matches!(kind, 1 | 5) {
            let header = avc_rbsp(&nal[1..nal.len().min(65)]);
            let mut bits = Bits {
                bytes: &header,
                position: 0,
            };
            if bits.ue()? >= codec.macroblocks || bits.ue()? > 9 {
                return Err(invalid("view-once AVC slice header is invalid"));
            }
            let pps_id = bits.ue()? as usize;
            if pps_id > 255 || codec.pps_ids[pps_id / 64] & (1 << (pps_id % 64)) == 0 {
                return Err(invalid("view-once AVC slice references unknown PPS"));
            }
        }
        slice |= matches!(kind, 1 | 5);
        bytes = &bytes[len..];
    }
    if !slice {
        return Err(invalid("view-once AVC sample has no video slice"));
    }
    Ok(())
}

fn validate_avcc(bytes: &[u8], width: u32, height: u32) -> Result<(usize, [u64; 4]), AppError> {
    if bytes.len() < 7 || bytes[0] != 1 || bytes[4] & 0xfc != 0xfc || bytes[5] & 0xe0 != 0xe0 {
        return Err(invalid("view-once AVC configuration is invalid"));
    }
    let length_size = usize::from(bytes[4] & 3) + 1;
    if length_size == 3 {
        return Err(invalid("view-once AVC NAL length is invalid"));
    }
    let count = usize::from(bytes[5] & 31);
    if count == 0 || count > 8 {
        return Err(invalid("view-once AVC configuration has invalid SPS count"));
    }
    let mut offset = 6;
    let mut sps_ids = 0_u32;
    for _ in 0..count {
        let len = usize::from(u16_at(bytes, offset)?);
        offset += 2;
        let sps = bytes
            .get(offset..offset + len)
            .ok_or_else(|| invalid("view-once AVC SPS is truncated"))?;
        let (coded_width, coded_height, sps_id) = sps_dimensions(sps)?;
        if sps_ids & (1 << sps_id) != 0 {
            return Err(invalid("view-once AVC SPS identifier is duplicated"));
        }
        sps_ids |= 1 << sps_id;
        if coded_width != width || coded_height != height {
            return Err(invalid("view-once AVC coded dimensions disagree"));
        }
        offset += len;
    }
    let pps_count = usize::from(
        *bytes
            .get(offset)
            .ok_or_else(|| invalid("view-once AVC PPS is missing"))?,
    );
    offset += 1;
    if pps_count == 0 || pps_count > 8 {
        return Err(invalid("view-once AVC configuration has invalid PPS count"));
    }
    let mut pps_ids = [0_u64; 4];
    for _ in 0..pps_count {
        let len = usize::from(u16_at(bytes, offset)?);
        offset += 2;
        let pps = bytes
            .get(offset..offset + len)
            .ok_or_else(|| invalid("view-once AVC PPS is truncated"))?;
        if pps.len() < 2 || pps[0] & 0x9f != 8 {
            return Err(invalid("view-once AVC PPS is invalid"));
        }
        let rbsp = avc_rbsp(&pps[1..]);
        let mut bits = Bits {
            bytes: &rbsp,
            position: 0,
        };
        let pps_id = bits.ue()? as usize;
        let sps_id = bits.ue()?;
        if pps_id > 255 || sps_id > 31 {
            return Err(invalid("view-once AVC PPS identifiers are invalid"));
        }
        if pps_ids[pps_id / 64] & (1 << (pps_id % 64)) != 0 || sps_ids & (1 << sps_id) == 0 {
            return Err(invalid(
                "view-once AVC PPS references invalid parameter sets",
            ));
        }
        pps_ids[pps_id / 64] |= 1 << (pps_id % 64);
        bits.read(2)?;
        if bits.ue()? != 0 || bits.ue()? > 15 || bits.ue()? > 15 {
            return Err(invalid(
                "view-once AVC slice groups or references are unsupported",
            ));
        }
        bits.read(3)?;
        let initial_qp = bits.se()?;
        let initial_qs = bits.se()?;
        let chroma_qp = bits.se()?;
        if !(-26..=25).contains(&initial_qp)
            || !(-26..=25).contains(&initial_qs)
            || !(-12..=12).contains(&chroma_qp)
        {
            return Err(invalid("view-once AVC PPS quantization is invalid"));
        }
        bits.read(3)?;
        offset += len;
    }
    // High-profile extension is optional; when present its SPS extensions are not supported.
    if offset != bytes.len()
        && (bytes.len() - offset != 4
            || bytes[offset] & 0xfc != 0xfc
            || bytes[offset + 1] & 0xf8 != 0xf8
            || bytes[offset + 2] & 0xf8 != 0xf8
            || bytes[offset + 3] != 0)
    {
        return Err(invalid(
            "view-once AVC configuration has unsupported extensions",
        ));
    }
    Ok((length_size, pps_ids))
}

struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Bits<'_> {
    fn read(&mut self, count: usize) -> Result<u32, AppError> {
        if count > 32 || self.position + count > self.bytes.len() * 8 {
            return Err(invalid("view-once codec configuration is truncated"));
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1)
                | u32::from((self.bytes[self.position / 8] >> (7 - self.position % 8)) & 1);
            self.position += 1;
        }
        Ok(value)
    }
    fn ue(&mut self) -> Result<u32, AppError> {
        let mut zeros = 0;
        while self.read(1)? == 0 {
            zeros += 1;
            if zeros > 24 {
                return Err(invalid("view-once AVC integer is too large"));
            }
        }
        Ok((1_u32 << zeros) - 1 + self.read(zeros)?)
    }
    fn se(&mut self) -> Result<i32, AppError> {
        let value = self.ue()?;
        Ok(if value & 1 == 0 {
            -((value / 2) as i32)
        } else {
            value.div_ceil(2) as i32
        })
    }
}

fn avc_rbsp(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut rbsp = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut zeros = 0;
    for byte in bytes {
        if zeros == 2 && *byte == 3 {
            zeros = 0;
            continue;
        }
        rbsp.push(*byte);
        zeros = if *byte == 0 { zeros + 1 } else { 0 };
    }
    rbsp
}

fn sps_dimensions(nal: &[u8]) -> Result<(u32, u32, u32), AppError> {
    if nal.len() < 5 || nal[0] & 0x9f != 7 {
        return Err(invalid("view-once AVC SPS is invalid"));
    }
    let rbsp = avc_rbsp(&nal[1..]);
    let mut bits = Bits {
        bytes: &rbsp,
        position: 0,
    };
    let profile = bits.read(8)?;
    bits.read(8)?;
    let level = bits.read(8)?;
    let sps_id = bits.ue()?;
    if level > 52 || sps_id > 31 {
        return Err(invalid("view-once AVC profile exceeds limits"));
    }
    let mut chroma = 1;
    if matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma = bits.ue()?;
        if chroma > 3 || (chroma == 3 && bits.read(1)? != 0) || bits.ue()? > 2 || bits.ue()? > 2 {
            return Err(invalid("view-once AVC chroma profile is unsupported"));
        }
        bits.read(1)?;
        if bits.read(1)? != 0 {
            for index in 0..if chroma == 3 { 12 } else { 8 } {
                if bits.read(1)? != 0 {
                    let mut last = 8;
                    let mut next = 8;
                    for _ in 0..if index < 6 { 16 } else { 64 } {
                        if next != 0 {
                            next = (last + bits.se()? + 256).rem_euclid(256);
                        }
                        if next != 0 {
                            last = next;
                        }
                    }
                }
            }
        }
    } else if !matches!(profile, 66 | 77 | 88) {
        return Err(invalid("view-once AVC profile is unsupported"));
    }
    if bits.ue()? > 12 {
        return Err(invalid("view-once AVC frame index exceeds limits"));
    }
    match bits.ue()? {
        0 => {
            if bits.ue()? > 12 {
                return Err(invalid("view-once AVC frame order exceeds limits"));
            }
        }
        1 => {
            bits.read(1)?;
            bits.se()?;
            bits.se()?;
            let count = bits.ue()?;
            if count > 255 {
                return Err(invalid("view-once AVC frame cycle exceeds limits"));
            }
            for _ in 0..count {
                bits.se()?;
            }
        }
        2 => {}
        _ => return Err(invalid("view-once AVC frame order is invalid")),
    }
    let references = bits.ue()?;
    if references > 16 {
        return Err(invalid("view-once AVC reference frames exceed limits"));
    }
    bits.read(1)?;
    let width_mbs = bits.ue()? + 1;
    let height_maps = bits.ue()? + 1;
    let frame_only = bits.read(1)?;
    if frame_only == 0 {
        bits.read(1)?;
    }
    bits.read(1)?;
    let mut crop_x = 0;
    let mut crop_y = 0;
    if bits.read(1)? != 0 {
        crop_x = bits.ue()? + bits.ue()?;
        crop_y = bits.ue()? + bits.ue()?;
    }
    let frame_factor = 2 - frame_only;
    let crop_unit_x = if chroma == 1 || chroma == 2 { 2 } else { 1 };
    let crop_unit_y = if chroma == 1 {
        2 * frame_factor
    } else {
        frame_factor
    };
    // Bound coded allocation as well as cropped display dimensions.
    dimensions(width_mbs * 16, height_maps * 16 * frame_factor)?;
    if u64::from(width_mbs * 16)
        * u64::from(height_maps * 16 * frame_factor)
        * u64::from(references + 1)
        * 2
        > MAX_VIEW_ONCE_BYTES as u64
    {
        return Err(invalid(
            "view-once AVC decoded picture buffer exceeds limits",
        ));
    }
    let width = (width_mbs * 16)
        .checked_sub(crop_x * crop_unit_x)
        .ok_or_else(|| invalid("view-once AVC crop is invalid"))?;
    let height = (height_maps * 16 * frame_factor)
        .checked_sub(crop_y * crop_unit_y)
        .ok_or_else(|| invalid("view-once AVC crop is invalid"))?;
    dimensions(width, height)?;
    Ok((width, height, sps_id))
}

fn descriptor(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), AppError> {
    let tag = *bytes
        .first()
        .ok_or_else(|| invalid("view-once AAC descriptor is truncated"))?;
    let mut offset = 1;
    let mut len = 0_usize;
    loop {
        if offset > 4 {
            return Err(invalid("view-once AAC descriptor length is invalid"));
        }
        let byte = *bytes
            .get(offset)
            .ok_or_else(|| invalid("view-once AAC descriptor is truncated"))?;
        offset += 1;
        len = (len << 7) | usize::from(byte & 127);
        if byte & 128 == 0 {
            break;
        }
    }
    let body = bytes
        .get(offset..offset + len)
        .ok_or_else(|| invalid("view-once AAC descriptor is truncated"))?;
    Ok((tag, body, &bytes[offset + len..]))
}

fn validate_aac(bytes: &[u8]) -> Result<(), AppError> {
    full_box(bytes)?;
    let (tag, es, trailing) = descriptor(&bytes[4..])?;
    if tag != 3 || !trailing.is_empty() || es.len() < 3 || es[2] & 0xe0 != 0 {
        return Err(invalid("view-once AAC elementary stream is unsupported"));
    }
    let (tag, decoder, rest) = descriptor(&es[3..])?;
    if tag != 4 || decoder.len() < 13 || decoder[0] != 0x40 || decoder[1] != 0x15 {
        return Err(invalid("view-once AAC decoder is unsupported"));
    }
    let (tag, config, trailing) = descriptor(&decoder[13..])?;
    if tag != 5 || !trailing.is_empty() || config.len() < 2 || config.len() > 8 {
        return Err(invalid("view-once AAC configuration is invalid"));
    }
    let mut bits = Bits {
        bytes: config,
        position: 0,
    };
    if bits.read(5)? != 2
        || bits.read(4)? > 12
        || !(1..=2).contains(&bits.read(4)?)
        || bits.read(3)? != 0
    {
        return Err(invalid("view-once AAC profile is unsupported"));
    }
    let (tag, sl, trailing) = descriptor(rest)?;
    if tag != 6 || sl != [2] || !trailing.is_empty() {
        return Err(invalid("view-once AAC synchronization is unsupported"));
    }
    Ok(())
}
