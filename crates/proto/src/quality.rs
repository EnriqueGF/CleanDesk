//! Transmission quality profiles (spec section 8).

use serde::{Deserialize, Serialize};

/// A named transmission profile chosen by the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QualityProfile {
    /// Adapt codec, compression and FPS automatically to link conditions.
    #[default]
    Auto,
    /// Prioritise visual fidelity (design work, image review).
    Max,
    /// Balance fidelity and latency.
    Balanced,
    /// Prioritise low latency and low bandwidth (remote support).
    Performance,
}

/// Concrete encoder parameters derived from a [`QualityProfile`].
///
/// The [`Auto`](QualityProfile::Auto) profile is resolved at runtime from live
/// bandwidth/RTT estimates; the others map to fixed presets here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityParams {
    /// Target frames per second.
    pub target_fps: u16,
    /// JPEG/codec quality, 1..=100.
    pub quality: u8,
    /// Max chroma subsampling aggressiveness (true = 4:2:0, false = 4:4:4).
    pub subsample: bool,
}

impl QualityProfile {
    /// Fixed preset parameters. `Auto` returns the `Balanced` preset as a
    /// starting point before the adaptive controller takes over.
    pub fn params(self) -> QualityParams {
        match self {
            QualityProfile::Max => QualityParams { target_fps: 60, quality: 95, subsample: false },
            QualityProfile::Balanced | QualityProfile::Auto => {
                QualityParams { target_fps: 30, quality: 75, subsample: true }
            }
            QualityProfile::Performance => {
                QualityParams { target_fps: 24, quality: 50, subsample: true }
            }
        }
    }

    /// Human label (Spanish UI strings live in the GUI crate; this is neutral).
    pub fn label(self) -> &'static str {
        match self {
            QualityProfile::Auto => "auto",
            QualityProfile::Max => "max",
            QualityProfile::Balanced => "balanced",
            QualityProfile::Performance => "performance",
        }
    }
}
