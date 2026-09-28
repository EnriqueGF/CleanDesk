//! The capture → encode → send pipeline and the shared knobs that steer it.
//!
//! [`MediaControl`] is the single hand-off point between the async session
//! (which receives the viewer's wishes: quality, monitor, "send a keyframe")
//! and the dedicated capture thread (which owns the DXGI resources and cannot
//! be async). The capture thread polls it once per frame.
//!
//! # Adaptive quality
//!
//! `QualityProfile::Auto` (spec §8) is resolved here from the measured RTT:
//! a fast link gets the `Balanced` preset, a slow one steps down toward
//! `Performance`. RTT comes from the control-channel `Ping`/`Pong` exchange
//! driven by the stats task. The mapping is a pure function
//! ([`auto_params`]) so it is unit-tested.
//!
//! # Loss handling
//!
//! Encoded frames are handed to the sender through a small bounded queue. If
//! the network cannot keep up the queue fills; rather than block capture (and
//! let latency balloon) the frame is *dropped* — and because every delta
//! assumes the previous frame was delivered, dropping one forces the next
//! frame to be a keyframe.

use bytes::Bytes;
use cleandesk_codec::{RawFrame, TileEncoder, VideoEncoder};
use cleandesk_proto::{
    frame,
    media::{chunk_frame, MAX_CHUNK_PAYLOAD},
    message::{MonitorInfo, VideoFrame},
    quality::{QualityParams, QualityProfile},
};
use cleandesk_transport::{Channel, PeerConnection};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Encoded frames buffered between the capture thread and the sender task.
const SEND_QUEUE: usize = 3;

/// RTT above which `Auto` steps down one notch, and above which it goes to
/// the lowest preset.
const AUTO_RTT_DEGRADE_MS: u32 = 120;
const AUTO_RTT_WORST_MS: u32 = 300;

#[derive(Debug)]
struct Inner {
    quality: QualityProfile,
    monitor: MonitorInfo,
    /// Set by the session when the viewer picks another monitor; consumed by
    /// the capture thread.
    pending_monitor: Option<u16>,
    keyframe_requested: bool,
    /// Last measured round-trip time.
    rtt_ms: u32,
    /// Outstanding RTT probe: (nonce, sent-at).
    ping: Option<(u64, Instant)>,
    next_nonce: u64,
}

/// Live, shared media settings for one session. Cheap to clone (`Arc`).
#[derive(Clone, Debug)]
pub struct MediaControl {
    inner: Arc<Mutex<Inner>>,
    frames_sent: Arc<AtomicU32>,
    bytes_sent: Arc<AtomicU64>,
}

/// Numbers reported in `SessionStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub fps: u16,
    pub bandwidth_kbps: u32,
    pub rtt_ms: u32,
}

impl MediaControl {
    pub fn new(quality: QualityProfile, monitor: MonitorInfo) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                quality,
                monitor,
                pending_monitor: None,
                keyframe_requested: false,
                rtt_ms: 0,
                ping: None,
                next_nonce: 1,
            })),
            frames_sent: Arc::new(AtomicU32::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_quality(&self, q: QualityProfile) {
        self.inner.lock().quality = q;
    }

    pub fn quality(&self) -> QualityProfile {
        self.inner.lock().quality
    }

    /// The monitor input coordinates are currently mapped onto.
    pub fn monitor(&self) -> MonitorInfo {
        self.inner.lock().monitor.clone()
    }

    /// Ask the capture thread to switch to `monitor`. Input mapping switches
    /// immediately so the viewer's next click lands where it sees it.
    pub fn select_monitor(&self, monitor: MonitorInfo) {
        let mut g = self.inner.lock();
        g.pending_monitor = Some(monitor.index);
        g.monitor = monitor;
    }

    pub fn request_keyframe(&self) {
        self.inner.lock().keyframe_requested = true;
    }

    /// Mint a nonce for an RTT probe and remember when it was sent.
    pub fn issue_ping(&self) -> u64 {
        let mut g = self.inner.lock();
        let nonce = g.next_nonce;
        g.next_nonce = g.next_nonce.wrapping_add(1);
        g.ping = Some((nonce, Instant::now()));
        nonce
    }

    /// Record the echo of a probe; unknown nonces are ignored.
    pub fn observe_pong(&self, nonce: u64) {
        self.observe_pong_at(nonce, Instant::now());
    }

    fn observe_pong_at(&self, nonce: u64, now: Instant) {
        let mut g = self.inner.lock();
        if let Some((sent_nonce, sent_at)) = g.ping {
            if sent_nonce == nonce {
                g.rtt_ms = now.saturating_duration_since(sent_at).as_millis().min(u32::MAX as u128) as u32;
                g.ping = None;
            }
        }
    }

    pub fn rtt_ms(&self) -> u32 {
        self.inner.lock().rtt_ms
    }

    /// Reset the per-interval counters and report them as rates over `over`.
    pub fn take_snapshot(&self, over: Duration) -> StatsSnapshot {
        let secs = over.as_secs_f64().max(0.001);
        let frames = self.frames_sent.swap(0, Ordering::Relaxed);
        let bytes = self.bytes_sent.swap(0, Ordering::Relaxed);
        StatsSnapshot {
            fps: (f64::from(frames) / secs).round().min(f64::from(u16::MAX)) as u16,
            bandwidth_kbps: ((bytes as f64) * 8.0 / 1000.0 / secs).round().min(f64::from(u32::MAX)) as u32,
            rtt_ms: self.rtt_ms(),
        }
    }

    /// Take the pending capture-thread commands: (params to use, monitor to
    /// switch to if any, whether a keyframe was requested).
    fn poll(&self) -> (QualityParams, Option<u16>, bool) {
        let mut g = self.inner.lock();
        let params = resolve_params(g.quality, g.rtt_ms);
        let mon = g.pending_monitor.take();
        let kf = std::mem::take(&mut g.keyframe_requested);
        (params, mon, kf)
    }
}

/// Encoder parameters for a profile given the measured RTT. Fixed profiles
/// ignore RTT; `Auto` degrades as latency climbs.
pub fn resolve_params(profile: QualityProfile, rtt_ms: u32) -> QualityParams {
    match profile {
        QualityProfile::Auto => auto_params(rtt_ms),
        other => other.params(),
    }
}

/// The `Auto` ladder: Balanced on a good link, an intermediate step, then
/// Performance on a bad one.
pub fn auto_params(rtt_ms: u32) -> QualityParams {
    if rtt_ms >= AUTO_RTT_WORST_MS {
        QualityProfile::Performance.params()
    } else if rtt_ms >= AUTO_RTT_DEGRADE_MS {
        QualityParams { target_fps: 24, quality: 60, subsample: true }
    } else {
        QualityProfile::Balanced.params()
    }
}

/// Spawn the capture→encode thread and the video-send task.
pub(crate) fn start_media(peer: Arc<PeerConnection>, control: MediaControl) {
    let (tx, mut rx) = mpsc::channel::<VideoFrame>(SEND_QUEUE);

    // Capture + encode live on a dedicated OS thread: the DXGI capturer holds
    // COM/D3D11 resources that are not `Send`, so they must never cross threads.
    let thread_control = control.clone();
    std::thread::Builder::new()
        .name("cleandesk-capture".into())
        .spawn(move || capture_loop(thread_control, tx))
        .map(|_| ())
        .unwrap_or_else(|e| error!(error = %e, "failed to spawn capture thread"));

    tokio::spawn(async move {
        while let Some(vf) = rx.recv().await {
            let chunks = match chunk_frame(&vf, MAX_CHUNK_PAYLOAD) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "frame too large to chunk; skipping");
                    control.request_keyframe();
                    continue;
                }
            };
            let mut sent_bytes = 0u64;
            for chunk in chunks {
                match frame::encode_payload(&chunk) {
                    Ok(bytes) => {
                        sent_bytes += bytes.len() as u64;
                        if peer.send(Channel::Video, Bytes::from(bytes)).await.is_err() {
                            return; // channel closed -> session over
                        }
                    }
                    Err(e) => warn!(error = %e, "chunk encode failed"),
                }
            }
            control.frames_sent.fetch_add(1, Ordering::Relaxed);
            control.bytes_sent.fetch_add(sent_bytes, Ordering::Relaxed);
        }
    });
}

/// Body of the capture thread.
fn capture_loop(control: MediaControl, tx: mpsc::Sender<VideoFrame>) {
    let mut capturer = match cleandesk_capture::new_capturer() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to start screen capture");
            return;
        }
    };
    let (mut params, _, _) = control.poll();
    let mut encoder = TileEncoder::new(params);
    let mut last_sent = Instant::now() - Duration::from_secs(1);
    let mut current_monitor = control.monitor().index;
    if let Err(e) = capturer.select_monitor(current_monitor) {
        debug!(error = %e, "initial monitor selection failed; using capturer default");
    }

    loop {
        let (wanted, monitor, keyframe) = control.poll();
        if wanted != params {
            params = wanted;
            encoder.set_quality(params);
            encoder.force_keyframe();
        }
        if let Some(index) = monitor {
            if index != current_monitor {
                match capturer.select_monitor(index) {
                    Ok(()) => {
                        current_monitor = index;
                        encoder.force_keyframe();
                    }
                    Err(e) => warn!(error = %e, index, "monitor switch failed"),
                }
            }
        }
        if keyframe {
            encoder.force_keyframe();
        }

        // Pace to the target FPS: DXGI only wakes us on change, but a busy
        // screen (video playback) would otherwise be encoded at full rate.
        let interval = Duration::from_secs_f64(1.0 / f64::from(params.target_fps.max(1)));
        let since = last_sent.elapsed();
        if since < interval {
            std::thread::sleep(interval - since);
        }

        match capturer.next_frame(Duration::from_millis(100)) {
            Ok(Some(cf)) => {
                let raw = RawFrame {
                    width: cf.width,
                    height: cf.height,
                    stride: cf.stride,
                    bgra: &cf.bgra,
                    timestamp_us: cf.timestamp_us,
                };
                match encoder.encode(raw) {
                    Ok(vf) => match tx.try_send(vf) {
                        Ok(()) => last_sent = Instant::now(),
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // The sender is behind: drop this frame and make
                            // sure the next one is self-contained.
                            debug!("send queue full; dropping frame");
                            encoder.force_keyframe();
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    },
                    Err(e) => warn!(error = %e, "encode failed"),
                }
            }
            Ok(None) => {
                if tx.is_closed() {
                    break;
                }
            }
            Err(e) => {
                debug!(error = %e, "capture error");
                if tx.is_closed() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    debug!("capture thread stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mon() -> MonitorInfo {
        MonitorInfo { index: 0, width: 1920, height: 1080, primary: true, origin_x: 0, origin_y: 0 }
    }

    #[test]
    fn auto_ladder_degrades_with_rtt() {
        assert_eq!(auto_params(0), QualityProfile::Balanced.params());
        assert_eq!(auto_params(AUTO_RTT_DEGRADE_MS - 1), QualityProfile::Balanced.params());
        let mid = auto_params(AUTO_RTT_DEGRADE_MS);
        assert!(mid.quality < QualityProfile::Balanced.params().quality);
        assert!(mid.quality > QualityProfile::Performance.params().quality);
        assert_eq!(auto_params(AUTO_RTT_WORST_MS), QualityProfile::Performance.params());
        assert_eq!(resolve_params(QualityProfile::Max, 10_000), QualityProfile::Max.params());
    }

    #[test]
    fn ping_pong_measures_rtt_and_ignores_stale_nonces() {
        let c = MediaControl::new(QualityProfile::Auto, mon());
        let n1 = c.issue_ping();
        let t = Instant::now();
        c.observe_pong_at(n1 + 100, t + Duration::from_millis(500));
        assert_eq!(c.rtt_ms(), 0, "unknown nonce must not update RTT");
        let n2 = c.issue_ping();
        let sent = c.inner.lock().ping.unwrap().1;
        c.observe_pong_at(n2, sent + Duration::from_millis(42));
        assert_eq!(c.rtt_ms(), 42);
        // A second pong for the same probe is ignored.
        c.observe_pong_at(n2, sent + Duration::from_millis(999));
        assert_eq!(c.rtt_ms(), 42);
    }

    #[test]
    fn poll_consumes_one_shot_commands() {
        let c = MediaControl::new(QualityProfile::Balanced, mon());
        let m2 = MonitorInfo { index: 1, width: 800, height: 600, primary: false, origin_x: 1920, origin_y: 0 };
        c.select_monitor(m2.clone());
        c.request_keyframe();
        assert_eq!(c.monitor(), m2, "input mapping switches immediately");
        let (params, mon, kf) = c.poll();
        assert_eq!(params, QualityProfile::Balanced.params());
        assert_eq!(mon, Some(1));
        assert!(kf);
        let (_, mon, kf) = c.poll();
        assert_eq!(mon, None);
        assert!(!kf);
    }

    #[test]
    fn snapshot_reports_rates_and_resets() {
        let c = MediaControl::new(QualityProfile::Auto, mon());
        c.frames_sent.store(60, Ordering::Relaxed);
        c.bytes_sent.store(250_000, Ordering::Relaxed);
        let s = c.take_snapshot(Duration::from_secs(2));
        assert_eq!(s.fps, 30);
        assert_eq!(s.bandwidth_kbps, 1000);
        let s = c.take_snapshot(Duration::from_secs(2));
        assert_eq!(s.fps, 0);
        assert_eq!(s.bandwidth_kbps, 0);
    }
}
