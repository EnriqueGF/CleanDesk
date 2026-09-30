//! Adversarial and multi-frame tests against the public API.
//!
//! `TileDecoder` consumes `VideoFrame`s straight off the network, so every
//! field is attacker-controlled. Each hostile case below must come back as
//! `Err` — never a panic, and never an allocation sized by the hostile
//! values (the `u32::MAX` cases would abort the process if it were).
//! Malformed cases that need the crate-private payload format live as unit
//! tests inside the decoder module instead.

use rotodesk_codec::{
    CodecError, DecodedImage, RawFrame, TileDecoder, TileEncoder, VideoDecoder, VideoEncoder, MAX_DIMENSION,
    MAX_PIXELS, TILE_SIZE,
};
use rotodesk_proto::{message::VideoFrame, quality::QualityParams};

fn params() -> QualityParams {
    QualityParams { target_fps: 30, quality: 75, subsample: true }
}

/// Tightly packed BGRA gradient (same pattern as `roundtrip.rs`).
fn gradient(width: u32, height: u32) -> Vec<u8> {
    let mut bgra = vec![0u8; width as usize * height as usize * 4];
    for y in 0..height {
        for x in 0..width {
            let i = (y as usize * width as usize + x as usize) * 4;
            bgra[i..i + 4].copy_from_slice(&[((x + y) % 256) as u8, (y % 256) as u8, (x % 256) as u8, 255]);
        }
    }
    bgra
}

fn encode(encoder: &mut TileEncoder, width: u32, height: u32, bgra: &[u8]) -> VideoFrame {
    encoder
        .encode(RawFrame { width, height, stride: width as usize * 4, bgra, timestamp_us: 0 })
        .expect("well-formed frames must encode")
}

/// A genuine keyframe to mutate into hostile variants.
fn valid_keyframe(width: u32, height: u32) -> VideoFrame {
    encode(&mut TileEncoder::new(params()), width, height, &gradient(width, height))
}

fn codec_error(err: &anyhow::Error) -> Option<&CodecError> {
    err.downcast_ref::<CodecError>()
}

/// Deterministic pseudo-random bytes (xorshift) so the test needs no extra
/// dependency and reproduces exactly.
fn garbage(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

#[test]
fn u32_max_dimensions_are_rejected_before_any_allocation() {
    let hostile = VideoFrame {
        sequence: 0,
        width: u32::MAX,
        height: u32::MAX,
        keyframe: true,
        timestamp_us: 0,
        data: vec![0x28, 0xB5, 0x2F, 0xFD], // zstd magic and nothing else
    };
    let err = TileDecoder::new().decode(&hostile).unwrap_err();
    assert!(
        matches!(codec_error(&err), Some(CodecError::FrameTooLarge { max, .. }) if *max == MAX_DIMENSION),
        "{err:?}"
    );
}

#[test]
fn dimensions_just_over_the_limit_are_rejected_but_the_limit_itself_is_allowed_through() {
    let mut frame = valid_keyframe(64, 64);
    for (w, h) in [(MAX_DIMENSION + 1, 64), (64, MAX_DIMENSION + 1), (65535, 65535)] {
        frame.width = w;
        frame.height = h;
        let err = TileDecoder::new().decode(&frame).unwrap_err();
        assert!(matches!(codec_error(&err), Some(CodecError::FrameTooLarge { .. })), "{w}x{h}: {err:?}");
    }
    // Exactly MAX_DIMENSION passes the size gate; it then fails on the grid
    // (the payload is for 64x64), proving the gate is not off by one.
    frame.width = MAX_DIMENSION;
    frame.height = 64;
    let err = TileDecoder::new().decode(&frame).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::GridMismatch { .. })), "{err:?}");
}

#[test]
fn frames_over_the_pixel_budget_are_rejected_even_when_each_side_is_legal() {
    // 8192x8192 respects MAX_DIMENSION per side but would cost a 256 MiB
    // canvas plus a 256 MiB copy per keyframe; the area cap stops it.
    let mut frame = valid_keyframe(64, 64);
    frame.width = MAX_DIMENSION;
    frame.height = MAX_DIMENSION;
    let err = TileDecoder::new().decode(&frame).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::FrameAreaTooLarge { .. })), "{err:?}");
    assert!(u64::from(MAX_DIMENSION) * u64::from(MAX_DIMENSION) > MAX_PIXELS);
    // The encoder refuses to produce such a frame as well.
    let (w, h) = (MAX_DIMENSION, MAX_DIMENSION);
    let bgra = vec![0u8; 64];
    let err = TileEncoder::new(params())
        .encode(RawFrame { width: w, height: h, stride: w as usize * 4, bgra: &bgra, timestamp_us: 0 })
        .unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::FrameAreaTooLarge { .. })), "{err:?}");
}

#[test]
fn encoder_rejects_oversized_frames_too() {
    let mut encoder = TileEncoder::new(params());
    // A stride/buffer that would be "valid" for the claimed width, so the
    // dimension check is what fires, not the buffer-size one.
    let bgra = vec![0u8; 16];
    let err = encoder
        .encode(RawFrame { width: MAX_DIMENSION + 1, height: 1, stride: 4, bgra: &bgra, timestamp_us: 0 })
        .unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::FrameTooLarge { .. })), "{err:?}");
}

#[test]
fn random_garbage_data_is_rejected() {
    let mut frame = valid_keyframe(128, 128);
    for seed in 1..=8u64 {
        frame.data = garbage(512 * seed as usize, seed);
        assert!(TileDecoder::new().decode(&frame).is_err(), "seed {seed} should fail");
    }
    frame.data = Vec::new();
    assert!(TileDecoder::new().decode(&frame).is_err(), "empty data should fail");
}

#[test]
fn truncated_zstd_stream_is_rejected() {
    let good = valid_keyframe(256, 256);
    for keep in [1, 4, 16, good.data.len() / 2, good.data.len() - 1] {
        let frame = VideoFrame { data: good.data[..keep].to_vec(), ..good.clone() };
        assert!(TileDecoder::new().decode(&frame).is_err(), "truncated to {keep} bytes should fail");
    }
}

#[test]
fn bit_flipped_stream_never_panics() {
    let good = valid_keyframe(200, 150);
    for pos in (0..good.data.len()).step_by(37) {
        let mut frame = good.clone();
        frame.data[pos] ^= 0x5A;
        // Either outcome is acceptable (zstd has a checksum, but a flip in
        // an unprotected header byte may still decode); what matters is
        // the call returns.
        let _ = TileDecoder::new().decode(&frame);
    }
}

#[test]
fn decompression_bomb_is_rejected_without_materializing_it() {
    // 32 MiB of zeros compresses to a few hundred bytes. With a 1x1 frame
    // the decoder's budget is ~1 MiB, so it must give up long before 32 MiB.
    let zeros = vec![0u8; 32 * 1024 * 1024];
    let bomb = zstd::encode_all(&zeros[..], 3).unwrap();
    assert!(bomb.len() < 8 * 1024, "bomb should be tiny on the wire ({} bytes)", bomb.len());
    let frame = VideoFrame { sequence: 0, width: 1, height: 1, keyframe: true, timestamp_us: 0, data: bomb };
    let err = TileDecoder::new().decode(&frame).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::PayloadTooLarge { .. })), "{err:?}");
}

#[test]
fn decompression_bomb_with_maximal_valid_dimensions_hits_the_hard_cap() {
    // Even at 8192x8192 (raw RGBA = 256 MiB) the payload budget is capped at
    // a fixed constant well below that, so a bomb larger than the cap is
    // still rejected rather than fully materialized.
    let zeros = vec![0u8; 80 * 1024 * 1024];
    let bomb = zstd::encode_all(&zeros[..], 3).unwrap();
    // 8192x4320 is the largest area the codec accepts (raw RGBA ≈ 135 MiB).
    let frame = VideoFrame {
        sequence: 0,
        width: MAX_DIMENSION,
        height: (MAX_PIXELS / u64::from(MAX_DIMENSION)) as u32,
        keyframe: true,
        timestamp_us: 0,
        data: bomb,
    };
    let err = TileDecoder::new().decode(&frame).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::PayloadTooLarge { .. })), "{err:?}");
}

#[test]
fn full_hd_gradient_keyframe_round_trips_under_the_payload_limit() {
    // The bound must never reject real content. A 1920x1080 gradient is the
    // worst realistic case for this codec: every tile is non-flat, so the
    // payload is as large as a keyframe of that size gets.
    let (width, height) = (1920, 1080);
    let bgra = gradient(width, height);
    let mut encoder = TileEncoder::new(params());
    let mut decoder = TileDecoder::new();
    let key = encode(&mut encoder, width, height, &bgra);
    let decoded = decoder.decode(&key).expect("a real Full HD keyframe must decode");
    assert_eq!((decoded.width, decoded.height), (width, height));
    assert_eq!(decoded.rgba.len(), width as usize * height as usize * 4);
    // The gradient repeats every 256 px, so an arbitrary interior pixel
    // must be close to its source value.
    let (x, y) = (1000usize, 700usize);
    let i = (y * width as usize + x) * 4;
    let (r, g, b) = (decoded.rgba[i] as i32, decoded.rgba[i + 1] as i32, decoded.rgba[i + 2] as i32);
    assert!((r - (x % 256) as i32).abs() < 24 && (g - (y % 256) as i32).abs() < 24);
    assert!((b - ((x + y) % 256) as i32).abs() < 24);
    assert_eq!(decoded.rgba[i + 3], 255);
}

#[test]
fn delta_after_keyframe_of_a_different_size_is_rejected_with_missing_keyframe() {
    let mut decoder = TileDecoder::new();
    decoder.decode(&valid_keyframe(128, 128)).unwrap();

    let mut small_encoder = TileEncoder::new(params());
    let small = gradient(64, 64);
    let _key = encode(&mut small_encoder, 64, 64, &small);
    let delta = encode(&mut small_encoder, 64, 64, &small);
    assert!(!delta.keyframe);

    let err = decoder.decode(&delta).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::MissingKeyframe)), "{err:?}");

    // A lying delta (keyframe payload with the flag cleared) at the wrong
    // size is rejected the same way, before any tile is touched.
    let mut lying = valid_keyframe(64, 64);
    lying.keyframe = false;
    let err = decoder.decode(&lying).unwrap_err();
    assert!(matches!(codec_error(&err), Some(CodecError::MissingKeyframe)), "{err:?}");
}

#[test]
fn delta_with_one_changed_tile_only_touches_that_tile_region() {
    let (width, height) = (256, 192);
    let mut bgra = gradient(width, height);
    let mut encoder = TileEncoder::new(params());
    let mut decoder = TileDecoder::new();

    let key = encode(&mut encoder, width, height, &bgra);
    let before: DecodedImage = decoder.decode(&key).unwrap();

    // Paint tile (2, 1) — pixels x in [128,192), y in [64,128) — solid white.
    let (tx, ty) = (2u32, 1u32);
    for y in ty * TILE_SIZE..(ty + 1) * TILE_SIZE {
        for x in tx * TILE_SIZE..(tx + 1) * TILE_SIZE {
            let i = (y as usize * width as usize + x as usize) * 4;
            bgra[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
        }
    }
    let delta = encode(&mut encoder, width, height, &bgra);
    assert!(!delta.keyframe);
    assert!(delta.data.len() * 4 < key.data.len(), "one dirty tile should be far smaller than a keyframe");

    let after = decoder.decode(&delta).unwrap();
    assert_eq!(after.rgba.len(), before.rgba.len());

    let mut changed_inside = 0usize;
    for y in 0..height {
        for x in 0..width {
            let i = (y as usize * width as usize + x as usize) * 4;
            let inside = (tx * TILE_SIZE..(tx + 1) * TILE_SIZE).contains(&x)
                && (ty * TILE_SIZE..(ty + 1) * TILE_SIZE).contains(&y);
            if inside {
                if after.rgba[i..i + 4] != before.rgba[i..i + 4] {
                    changed_inside += 1;
                }
                // Solid white through JPEG must still come out near white.
                assert!(
                    after.rgba[i..i + 3].iter().all(|&c| c > 240),
                    "pixel ({x},{y}) not white: {:?}",
                    &after.rgba[i..i + 4]
                );
            } else {
                assert_eq!(
                    after.rgba[i..i + 4],
                    before.rgba[i..i + 4],
                    "pixel ({x},{y}) outside the dirty tile changed"
                );
            }
        }
    }
    assert!(changed_inside > 0, "the dirty tile must actually have been repainted");
}

#[test]
fn decode_into_reuses_the_caller_buffer_and_matches_decode() {
    let (width, height) = (130, 70);
    let bgra = gradient(width, height);
    let mut encoder = TileEncoder::new(params());
    let key = encode(&mut encoder, width, height, &bgra);

    let expected = TileDecoder::new().decode(&key).unwrap();

    let mut decoder = TileDecoder::new();
    let mut buf = Vec::with_capacity(width as usize * height as usize * 4);
    let ptr_before = buf.as_ptr();
    let dims = decoder.decode_into(&key, &mut buf).unwrap();
    assert_eq!(dims, (width, height));
    assert_eq!(buf, expected.rgba);
    assert_eq!(buf.as_ptr(), ptr_before, "a large-enough buffer must be reused, not reallocated");

    // Second frame into the same buffer: still no reallocation.
    let delta = encode(&mut encoder, width, height, &bgra);
    decoder.decode_into(&delta, &mut buf).unwrap();
    assert_eq!(buf.as_ptr(), ptr_before);
    assert_eq!(buf, expected.rgba, "an unchanged delta must leave the image identical");
}
