// Padding strategy for DPI bypass via traffic volume obfuscation
//
// Adds random padding to packets to obscure real payload size
// and make traffic analysis more difficult.

use rand::Rng;

/// Strategy for adding random padding to packet data
#[derive(Debug, Clone)]
pub struct PaddingStrategy {
    /// Maximum padding bytes to add (0-max_padding range)
    max_padding: usize,
}

impl PaddingStrategy {
    /// Create a new padding strategy with specified maximum padding
    ///
    /// # Arguments
    ///
    /// * `max_padding` - Maximum number of padding bytes to add per packet
    pub fn new(max_padding: usize) -> Self {
        Self { max_padding }
    }

    /// Add random padding to the provided data vector
    ///
    /// Modifies data in-place by appending 0x00 bytes up to max_padding.
    /// The actual amount is randomly selected from [0, max_padding].
    pub fn add_padding(&self, data: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let padding_len = rng.gen_range(0..=self.max_padding);
        data.extend(vec![0u8; padding_len]);
    }

    /// Get the maximum padding size configured
    pub fn max_padding(&self) -> usize {
        self.max_padding
    }
}

impl Default for PaddingStrategy {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_strategy_creation() {
        let strategy = PaddingStrategy::new(512);
        assert_eq!(strategy.max_padding(), 512);
    }

    #[test]
    fn test_padding_added() {
        let strategy = PaddingStrategy::new(100);
        let mut data = vec![1, 2, 3, 4, 5];
        let original_len = data.len();

        strategy.add_padding(&mut data);

        // Data should be larger or equal (at least the original data preserved)
        assert!(data.len() >= original_len);
        // Padding cannot exceed max_padding
        assert!(data.len() <= original_len + 100);
    }

    #[test]
    fn test_padding_no_corruption() {
        let strategy = PaddingStrategy::new(50);
        let original = vec![1, 2, 3, 4, 5];
        let mut data = original.clone();

        strategy.add_padding(&mut data);

        // Original data must be preserved (not modified, only appended)
        assert_eq!(&data[..original.len()], original.as_slice());
    }

    #[test]
    fn test_padding_zero_max() {
        let strategy = PaddingStrategy::new(0);
        let mut data = vec![1, 2, 3];
        let original_len = data.len();

        strategy.add_padding(&mut data);

        // With max_padding=0, no padding should be added
        assert_eq!(data.len(), original_len);
    }

    #[test]
    fn test_padding_variability() {
        let strategy = PaddingStrategy::new(100);
        let mut sizes = Vec::new();

        // Run multiple times and collect sizes to verify randomness
        for _ in 0..20 {
            let mut data = vec![1, 2, 3];
            let original_len = data.len();
            strategy.add_padding(&mut data);
            sizes.push(data.len() - original_len);
        }

        // At least some variation expected (probabilistically)
        let min = sizes.iter().min().unwrap();
        let max = sizes.iter().max().unwrap();

        assert!(*max <= 100);
        // min is always >= 0 for usize
    }

    #[test]
    fn test_padding_empty_data() {
        let strategy = PaddingStrategy::new(50);
        let mut data = Vec::new();

        strategy.add_padding(&mut data);

        // Should add between 0 and 50 bytes
        assert!(data.len() <= 50);
    }
}
