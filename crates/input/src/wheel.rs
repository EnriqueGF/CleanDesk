//! Retain precision-wheel fractions between injections, independently per axis.
#[derive(Default)]
pub(crate) struct WheelAccumulator {
    remainder: [f64; 2],
}

impl WheelAccumulator {
    pub fn push(&mut self, x: f32, y: f32) -> [i32; 2] {
        [self.axis(0, x), self.axis(1, y)]
    }

    fn axis(&mut self, axis: usize, delta: f32) -> i32 {
        if !delta.is_finite() {
            return 0;
        }
        // Bound peer-controlled deltas without carrying an oversized residual.
        let total = f64::from(delta.clamp(-1024.0, 1024.0)) * 120.0 + self.remainder[axis];
        let units = total.round() as i32;
        self.remainder[axis] = total - f64::from(units);
        units
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_deltas_preserve_total_distance_on_both_axes() {
        let mut wheel = WheelAccumulator::default();
        let mut total = [0, 0];
        for _ in 0..1024 {
            let [x, y] = wheel.push(1.0 / 1024.0, -1.0 / 1024.0);
            total[0] += x;
            total[1] += y;
        }
        assert_eq!(total, [120, -120]);
        assert_eq!(wheel.push(-1.0, 1.0), [-120, 120]);
    }

    #[test]
    fn invalid_and_extreme_deltas_do_not_poison_following_events() {
        let mut wheel = WheelAccumulator::default();
        assert_eq!(wheel.push(f32::NAN, f32::INFINITY), [0, 0]);
        assert_eq!(wheel.push(f32::MAX, -f32::MAX), [122880, -122880]);
        assert_eq!(wheel.push(1.0, -0.5), [120, -60]);
    }
}
