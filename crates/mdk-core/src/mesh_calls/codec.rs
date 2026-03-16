//! Audio codec abstraction for mesh calls
//!
//! MDK provides the encryption and transport layers. The application provides
//! the codec implementation (e.g. Opus via the `opus` or `audiopus` crate).
//!
//! ## Usage
//!
//! ```rust,ignore
//! use mdk_core::mesh_calls::codec::{AudioCodec, AudioConfig};
//!
//! // Application provides an Opus implementation:
//! struct OpusCodec { encoder: opus::Encoder, decoder: opus::Decoder }
//!
//! impl AudioCodec for OpusCodec {
//!     fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, CodecError> { ... }
//!     fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, CodecError> { ... }
//! }
//!
//! // Then wire it into the call:
//! let pipeline = AudioPipeline::new(opus_codec, sframe_ctx, track);
//! pipeline.send_pcm(&pcm_samples).await?;
//! ```

use super::types::MeshCallError;

/// Audio configuration for codec initialization
#[derive(Debug, Clone, Copy)]
pub struct AudioConfig {
    /// Sample rate in Hz (typically 48000 for Opus)
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo)
    pub channels: u16,
    /// Frame duration in milliseconds (typically 20 for Opus)
    pub frame_duration_ms: u32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            frame_duration_ms: 20,
        }
    }
}

impl AudioConfig {
    /// Number of PCM samples per frame (per channel)
    pub fn samples_per_frame(&self) -> usize {
        (self.sample_rate as usize * self.frame_duration_ms as usize) / 1000
    }

    /// Total samples per frame including all channels
    pub fn total_samples_per_frame(&self) -> usize {
        self.samples_per_frame() * self.channels as usize
    }

    /// RTP timestamp increment per frame
    pub fn rtp_timestamp_increment(&self) -> u32 {
        self.sample_rate * self.frame_duration_ms / 1000
    }
}

/// Codec error type
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Encoding failed
    #[error("encode failed: {0}")]
    EncodeFailed(String),
    /// Decoding failed
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    /// Invalid input
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<CodecError> for MeshCallError {
    fn from(e: CodecError) -> Self {
        MeshCallError::WebRTC(format!("Codec error: {}", e))
    }
}

/// Trait for audio codecs (e.g. Opus)
///
/// Applications implement this trait to provide audio encoding/decoding.
/// MDK handles encryption and transport.
pub trait AudioCodec: Send {
    /// Encode PCM samples to compressed audio.
    ///
    /// `pcm` contains interleaved PCM samples (i16) for one frame duration.
    /// Returns the compressed audio data.
    fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, CodecError>;

    /// Decode compressed audio back to PCM samples.
    ///
    /// `data` contains one frame of compressed audio.
    /// Returns interleaved PCM samples (i16).
    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, CodecError>;

    /// Decode with packet loss concealment (PLC).
    ///
    /// Called when a frame is lost. The codec should generate comfort noise
    /// or extrapolate from previous frames.
    ///
    /// Default implementation returns silence.
    fn decode_lost(&mut self, config: &AudioConfig) -> Vec<i16> {
        vec![0i16; config.total_samples_per_frame()]
    }

    /// Get the codec's audio configuration
    fn config(&self) -> AudioConfig;
}

/// A passthrough "codec" that treats raw PCM as the wire format.
/// Useful for testing without a real codec library.
#[derive(Debug, Clone)]
pub struct PcmPassthrough {
    config: AudioConfig,
}

impl PcmPassthrough {
    /// Create a new PCM passthrough codec
    pub fn new(config: AudioConfig) -> Self {
        Self { config }
    }
}

impl Default for PcmPassthrough {
    fn default() -> Self {
        Self::new(AudioConfig::default())
    }
}

impl AudioCodec for PcmPassthrough {
    fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, CodecError> {
        // Pack i16 samples as little-endian bytes
        let mut bytes = Vec::with_capacity(pcm.len() * 2);
        for &sample in pcm {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        Ok(bytes)
    }

    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, CodecError> {
        if data.len() % 2 != 0 {
            return Err(CodecError::InvalidInput("Odd byte count".into()));
        }
        let mut pcm = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks_exact(2) {
            pcm.push(i16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(pcm)
    }

    fn config(&self) -> AudioConfig {
        self.config
    }
}

/// Full audio pipeline: PCM → codec → SFrame → RTP (and reverse)
///
/// This ties together the codec, SFrame encryption, and WebRTC track
/// into a single send/receive API.
pub struct AudioPipeline<C: AudioCodec> {
    codec: C,
    rtp_timestamp: u32,
}

impl<C: AudioCodec> AudioPipeline<C> {
    /// Create a new audio pipeline
    pub fn new(codec: C) -> Self {
        Self {
            codec,
            rtp_timestamp: 0,
        }
    }

    /// Encode PCM to compressed audio, ready for SFrame encryption.
    ///
    /// Returns (compressed_data, rtp_timestamp).
    pub fn encode_frame(&mut self, pcm: &[i16]) -> Result<(Vec<u8>, u32), CodecError> {
        let compressed = self.codec.encode(pcm)?;
        let ts = self.rtp_timestamp;
        self.rtp_timestamp += self.codec.config().rtp_timestamp_increment();
        Ok((compressed, ts))
    }

    /// Decode compressed audio back to PCM samples.
    pub fn decode_frame(&mut self, data: &[u8]) -> Result<Vec<i16>, CodecError> {
        self.codec.decode(data)
    }

    /// Handle a lost frame (packet loss concealment).
    pub fn decode_lost_frame(&mut self) -> Vec<i16> {
        let config = self.codec.config();
        self.codec.decode_lost(&config)
    }

    /// Get the current RTP timestamp
    pub fn rtp_timestamp(&self) -> u32 {
        self.rtp_timestamp
    }

    /// Get a reference to the codec
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Get a mutable reference to the codec
    pub fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_defaults() {
        let config = AudioConfig::default();
        assert_eq!(config.sample_rate, 48000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.frame_duration_ms, 20);
        assert_eq!(config.samples_per_frame(), 960);
        assert_eq!(config.total_samples_per_frame(), 960);
        assert_eq!(config.rtp_timestamp_increment(), 960);
    }

    #[test]
    fn test_audio_config_stereo() {
        let config = AudioConfig {
            channels: 2,
            ..Default::default()
        };
        assert_eq!(config.samples_per_frame(), 960);
        assert_eq!(config.total_samples_per_frame(), 1920);
    }

    #[test]
    fn test_pcm_passthrough_roundtrip() {
        let mut codec = PcmPassthrough::default();

        // Generate a 20ms frame of sine wave at 440Hz
        let config = codec.config();
        let num_samples = config.samples_per_frame();
        let pcm: Vec<i16> = (0..num_samples)
            .map(|i| {
                let t = i as f64 / config.sample_rate as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();

        let encoded = codec.encode(&pcm).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        assert_eq!(pcm, decoded);
    }

    #[test]
    fn test_audio_pipeline_with_passthrough() {
        let codec = PcmPassthrough::default();
        let mut pipeline = AudioPipeline::new(codec);

        let pcm = vec![100i16, 200, -100, -200, 0];

        let (compressed, ts1) = pipeline.encode_frame(&pcm).unwrap();
        assert_eq!(ts1, 0);
        let decoded = pipeline.decode_frame(&compressed).unwrap();
        assert_eq!(pcm, decoded);

        // Second frame increments timestamp
        let (_, ts2) = pipeline.encode_frame(&pcm).unwrap();
        assert_eq!(ts2, 960); // 48000 * 20ms / 1000
    }

    #[test]
    fn test_pipeline_with_sframe() {
        use crate::mesh_calls::{
            derive_sframe_base_key, derive_sframe_key, MediaType, SFrameBits, SFrameContext,
        };

        let codec = PcmPassthrough::default();
        let mut pipeline = AudioPipeline::new(codec);

        let call_base_key = [0x42u8; 32];
        let bits = SFrameBits::default();

        let mut sender_ctx = SFrameContext::new(bits, 0);
        let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let key = derive_sframe_key(&base_key, kid).unwrap();
        sender_ctx.set_key(MediaType::Audio, key.clone());

        let mut receiver_ctx = SFrameContext::new(bits, 1);
        receiver_ctx.set_remote_key(MediaType::Audio, 0, 0, key);

        // Full path: PCM → encode → SFrame encrypt → SFrame decrypt → decode → PCM
        let pcm: Vec<i16> = (0..960).map(|i| (i % 256) as i16 - 128).collect();

        let (compressed, _ts) = pipeline.encode_frame(&pcm).unwrap();
        let encrypted = sender_ctx
            .encrypt(MediaType::Audio, &compressed, b"")
            .unwrap();
        let (_, decrypted) = receiver_ctx.decrypt(&encrypted, b"").unwrap();
        let recovered = pipeline.decode_frame(&decrypted).unwrap();

        assert_eq!(pcm, recovered);
    }
}
