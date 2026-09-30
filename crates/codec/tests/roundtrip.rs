//! End-to-end tests against the public API only (as a consumer such as
//! `rotodesk-host`/`rotodesk-client` would use it): build a `RawFrame`,
//! push it through `TileEncoder`, pull it back through `TileDecoder`, check
//! what comes out.

use rotodesk_codec::{DecodedImage, RawFrame, TileDecoder, TileEncoder, VideoDecoder, VideoEncoder};
use rotodesk_proto::quality::QualityParams;

fn balanced_params() -> QualityParams {
    QualityParams { target_fps: 30, quality: 75, subsample: true }
}

/// Build a tightly packed (stride == width * 4) solid-color BGRA buffer,
/// plus the RGBA8 buffer we expect a lossless decode to match.
fn make_solid(width: u32, height: u32, r: u8, g: u8, b: u8) -> (Vec<u8>, Vec<u8>) {
    let mut bgra = vec![0u8; width as usize * height as usize * 4];
    let mut expected_rgba = vec![0u8; width as usize * height as usize * 4];
    for px in bgra.chunks_exact_mut(4) {
        px.copy_from_slice(&[b, g, r, 255]);
    }
    for px in expected_rgba.chunks_exact_mut(4) {
        px.copy_from_slice(&[r, g, b, 255]);
    }
    (bgra, expected_rgba)
}

/// Same, but a smooth per-pixel gradient — exercises JPEG on non-flat content
/// instead of the (trivially compressible) all-DC solid case above.
fn make_gradient(width: u32, height: u32) -> (Vec<u8>, Vec<u8>) {
    let mut bgra = vec![0u8; width as usize * height as usize * 4];
    let mut expected_rgba = vec![0u8; width as usize * height as usize * 4];
    for y in 0..height {
        for x in 0..width {
            let i = (y as usize * width as usize + x as usize) * 4;
            let r = (x % 256) as u8;
            let g = (y % 256) as u8;
            let b = ((x + y) % 256) as u8;
            bgra[i..i + 4].copy_from_slice(&[b, g, r, 255]);
            expected_rgba[i..i + 4].copy_from_slice(&[r, g, b, 255]);
        }
    }
    (bgra, expected_rgba)
}

/// Mean absolute error over the R, G, B channels only (alpha is always forced
/// to 255 on both sides by design, so including it would just dilute the
/// metric with a channel that can never disagree).
fn mean_abs_color_error(decoded: &DecodedImage, expected_rgba: &[u8]) -> f64 {
    assert_eq!(decoded.rgba.len(), expected_rgba.len());
    let mut sum = 0u64;
    let mut n = 0u64;
    for (actual_px, expected_px) in decoded.rgba.chunks_exact(4).zip(expected_rgba.chunks_exact(4)) {
        for c in 0..3 {
            sum += (actual_px[c] as i64 - expected_px[c] as i64).unsigned_abs();
            n += 1;
        }
    }
    sum as f64 / n as f64
}

// A reasonable ceiling for JPEG at quality 75 on easy (flat/smooth) content.
const MAX_MEAN_ABS_ERROR: f64 = 8.0;

#[test]
fn roundtrip_solid_color_within_jpeg_error_threshold() {
    // Deliberately not a multiple of 64, to also exercise edge tiles.
    let (width, height) = (130, 100);
    let (bgra, expected_rgba) = make_solid(width, height, 200, 90, 40);
    let mut encoder = TileEncoder::new(balanced_params());
    let mut decoder = TileDecoder::new();

    let raw = RawFrame { width, height, stride: width as usize * 4, bgra: &bgra, timestamp_us: 1_000 };
    let wire = encoder.encode(raw).expect("encode should succeed");
    assert!(wire.keyframe, "the first frame must be a keyframe");

    let decoded = decoder.decode(&wire).expect("decode should succeed");
    assert_eq!(decoded.width, width);
    assert_eq!(decoded.height, height);
    assert_eq!(decoded.rgba.len(), (width * height * 4) as usize);

    let err = mean_abs_color_error(&decoded, &expected_rgba);
    assert!(err < MAX_MEAN_ABS_ERROR, "mean abs color error too high: {err}");
}

#[test]
fn roundtrip_gradient_within_jpeg_error_threshold() {
    let (width, height) = (256, 180);
    let (bgra, expected_rgba) = make_gradient(width, height);
    let mut encoder = TileEncoder::new(balanced_params());
    let mut decoder = TileDecoder::new();

    let raw = RawFrame { width, height, stride: width as usize * 4, bgra: &bgra, timestamp_us: 2_000 };
    let wire = encoder.encode(raw).expect("encode should succeed");
    let decoded = decoder.decode(&wire).expect("decode should succeed");

    assert_eq!((decoded.width, decoded.height), (width, height));
    let err = mean_abs_color_error(&decoded, &expected_rgba);
    assert!(err < MAX_MEAN_ABS_ERROR, "mean abs color error too high: {err}");
}

#[test]
fn identical_consecutive_frames_yield_a_much_smaller_delta() {
    let (width, height) = (256, 256);
    let (bgra, _) = make_gradient(width, height);
    let mut encoder = TileEncoder::new(balanced_params());
    let stride = width as usize * 4;

    let key = encoder
        .encode(RawFrame { width, height, stride, bgra: &bgra, timestamp_us: 0 })
        .unwrap();
    assert!(key.keyframe);
    assert_eq!(key.sequence, 0);

    // Same pixels again: every tile should compare equal to the stored
    // previous frame, so the delta payload carries zero tiles.
    let delta = encoder
        .encode(RawFrame { width, height, stride, bgra: &bgra, timestamp_us: 33_000 })
        .unwrap();
    assert!(!delta.keyframe, "an unchanged frame must not be re-sent as a keyframe");
    assert_eq!(delta.sequence, 1, "sequence must be monotonic");
    assert!(
        delta.data.len() * 5 < key.data.len(),
        "delta ({} bytes) should be much smaller than the keyframe ({} bytes)",
        delta.data.len(),
        key.data.len()
    );
}

#[test]
fn force_keyframe_makes_the_next_frame_a_keyframe() {
    let (width, height) = (96, 96);
    let (bgra, _) = make_solid(width, height, 10, 20, 30);
    let mut encoder = TileEncoder::new(balanced_params());
    let stride = width as usize * 4;
    let frame = || RawFrame { width, height, stride, bgra: &bgra, timestamp_us: 0 };

    let f1 = encoder.encode(frame()).unwrap();
    assert!(f1.keyframe, "first frame is always a keyframe");

    let f2 = encoder.encode(frame()).unwrap();
    assert!(!f2.keyframe, "unchanged second frame should be a delta");

    encoder.force_keyframe();
    let f3 = encoder.encode(frame()).unwrap();
    assert!(f3.keyframe, "force_keyframe() must make the *next* frame a keyframe");
}

#[test]
fn resolution_change_forces_keyframe_and_resizes_decoder_canvas() {
    let (bgra_a, _) = make_gradient(120, 90);
    let (bgra_b, _) = make_gradient(200, 150);
    let mut encoder = TileEncoder::new(balanced_params());
    let mut decoder = TileDecoder::new();

    let f1 = encoder
        .encode(RawFrame { width: 120, height: 90, stride: 120 * 4, bgra: &bgra_a, timestamp_us: 0 })
        .unwrap();
    assert!(f1.keyframe);
    let d1 = decoder.decode(&f1).unwrap();
    assert_eq!((d1.width, d1.height), (120, 90));
    assert_eq!(d1.rgba.len(), 120 * 90 * 4);

    let f2 = encoder
        .encode(RawFrame { width: 200, height: 150, stride: 200 * 4, bgra: &bgra_b, timestamp_us: 16_000 })
        .unwrap();
    assert!(f2.keyframe, "a resolution change must force a keyframe");

    let d2 = decoder.decode(&f2).unwrap();
    assert_eq!((d2.width, d2.height), (200, 150), "decoder canvas must resize to the new resolution");
    assert_eq!(d2.rgba.len(), 200 * 150 * 4);
}

#[test]
fn decoder_rejects_a_delta_before_any_keyframe() {
    // A well-behaved encoder never does this, but the decoder must not panic
    // or paint garbage if a delta somehow arrives first (e.g. a dropped
    // keyframe packet) — it should surface a clear error instead.
    let (width, height) = (64, 64);
    let (bgra, _) = make_solid(width, height, 1, 2, 3);
    let mut encoder = TileEncoder::new(balanced_params());
    encoder
        .encode(RawFrame { width, height, stride: width as usize * 4, bgra: &bgra, timestamp_us: 0 })
        .unwrap();
    let delta = encoder
        .encode(RawFrame { width, height, stride: width as usize * 4, bgra: &bgra, timestamp_us: 1 })
        .unwrap();
    assert!(!delta.keyframe);

    let mut decoder = TileDecoder::new();
    assert!(decoder.decode(&delta).is_err());
}
