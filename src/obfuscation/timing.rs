// Timing obfuscation for DPI bypass via jitter injection
//
// Adds random delays between packets to make timing-based analysis
// and traffic pattern detection more difficult.

use rand::Rng;
use tokio::time::{sleep, Duration};

/// Timing obfuscator that injects random delays (jitter) into packet flow
#[derive(Debug, Clone)]
pub struct TimingObfuscator {
    /// Minimum delay in milliseconds
    min_ms: u64,
    /// Maximum delay in milliseconds
    max_ms: u64,
}

impl TimingObfuscator {
    /// Create a new timing obfuscator with specified delay range
    ///
    /// # Arguments
    ///
    /// * `min_ms` - Minimum jitter delay in milliseconds
    /// * `max_ms` - Maximum jitter delay in milliseconds
    ///
    /// # Panics
    ///
    /// Panics if `min_ms > max_ms`
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        assert!(min_ms <= max_ms, "min_ms must be <= max_ms");
        Self { min_ms, max_ms }
    }

    /// Add random jitter (async delay) to obscure packet timing patterns
    ///
    /// Sleeps for a random duration between min_ms and max_ms (inclusive)
    /// to make traffic flow analysis more difficult for DPI systems.
    pub async fn add_jitter(&self) {
        // Generate random delay before entering async context to ensure Send safety
        let delay_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(self.min_ms..=self.max_ms)
        };
        sleep(Duration::from_millis(delay_ms)).await;
    }

    /// Get the minimum jitter delay
    pub fn min_ms(&self) -> u64 {
        self.min_ms
    }

    /// Get the maximum jitter delay
    pub fn max_ms(&self) -> u64 {
        self.max_ms
    }
}

impl Default for TimingObfuscator {
    /// Create default timing obfuscator with 50-200ms jitter
    fn default() -> Self {
        Self::new(50, 200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_obfuscator_creation() {
        let obfuscator = TimingObfuscator::new(100, 500);
        assert_eq!(obfuscator.min_ms(), 100);
        assert_eq!(obfuscator.max_ms(), 500);
    }

    #[test]
    #[should_panic]
    fn test_timing_obfuscator_invalid_range() {
        // min > max should panic
        let _ = TimingObfuscator::new(500, 100);
    }

    #[test]
    fn test_timing_obfuscator_valid_range() {
        // Equal min and max should be valid
        let obfuscator = TimingObfuscator::new(100, 100);
        assert_eq!(obfuscator.min_ms(), 100);
        assert_eq!(obfuscator.max_ms(), 100);
    }

    #[test]
    fn test_timing_obfuscator_default() {
        let obfuscator = TimingObfuscator::default();
        assert_eq!(obfuscator.min_ms(), 50);
        assert_eq!(obfuscator.max_ms(), 200);
    }

    #[tokio::test]
    async fn test_jitter_timing() {
        use std::time::Instant;

        let obfuscator = TimingObfuscator::new(10, 50); // Shorter delays for testing

        let start = Instant::now();
        obfuscator.add_jitter().await;
        let elapsed = start.elapsed();

        // Allow some margin (actual delay should be between 10-50ms + overhead)
        // We'll check that it's at least 5ms (accounting for overhead) and reasonable
        assert!(elapsed.as_millis() >= 5, "Jitter delay too short: {:?}", elapsed);
    }

    #[tokio::test]
    async fn test_jitter_multiple_calls_variant() {
        // Verify that multiple calls produce different delays (with high probability)
        let obfuscator = TimingObfuscator::new(20, 100);
        let mut durations = Vec::new();

        for _ in 0..5 {
            use std::time::Instant;
            let start = Instant::now();
            obfuscator.add_jitter().await;
            durations.push(start.elapsed().as_millis());
        }

        // At least some variation expected across multiple calls
        let min = durations.iter().min().unwrap();
        let max = durations.iter().max().unwrap();

        // With wide delay range, should see some variation (very high probability)
        // This is probabilistic but failure is extremely unlikely with these ranges
        assert!(*max > *min || durations.len() == 1);
    }

    #[test]
    fn test_timing_obfuscator_zero_delay() {
        let obfuscator = TimingObfuscator::new(0, 0);
        assert_eq!(obfuscator.min_ms(), 0);
        assert_eq!(obfuscator.max_ms(), 0);
    }
}
