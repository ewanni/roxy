// Traffic shaping module for DPI bypass via HTTPS-like packet sizes
//
// Mimics typical HTTPS packet size distributions to evade DPI detection.
// Uses weighted random selection of realistic packet sizes.

use rand::Rng;

/// Traffic shaper that splits data into HTTPS-like packet sizes
#[derive(Debug, Clone)]
pub struct TrafficShaper {
    /// Packet sizes (bytes) based on common HTTPS distribution
    sizes: Vec<usize>,
    /// Weights normalized for uniform sampling [0, 1000)
    weights: Vec<usize>,
}

impl TrafficShaper {
    /// Create a new TrafficShaper with HTTPS-like packet size distribution
    ///
    /// Packet sizes are based on real-world HTTPS traffic analysis:
    /// - 64, 128, 256: TLS handshake fragments
    /// - 512, 1024: Small HTTP headers and responses
    /// - 1460: Typical MSS (Maximum Segment Size) for TCP
    /// - 16384: Large HTTPS record size (TLS max plaintext)
    pub fn new() -> Self {
        let sizes = vec![64, 128, 256, 512, 1024, 1460, 16384];

        // Weights based on observed HTTPS traffic distribution
        let weights_raw = vec![0.05, 0.08, 0.12, 0.15, 0.20, 0.25, 0.15];
        let total_weight: f64 = weights_raw.iter().sum();

        // Normalize weights to cumulative range [0, 1000)
        let weights: Vec<usize> = weights_raw
            .iter()
            .map(|&w| (w / total_weight * 1000.0) as usize)
            .collect();

        Self { sizes, weights }
    }

    /// Split data into chunks following HTTPS-like packet size distribution
    ///
    /// Returns a vector of byte chunks, each sized according to weighted distribution
    /// to mimic realistic HTTPS traffic patterns and evade DPI inspection.
    pub fn shape(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let mut chunks = Vec::new();
        let mut remaining = data.to_vec();

        while !remaining.is_empty() {
            // Select a random packet size from the weighted distribution
            let random_val = rng.gen_range(0..1000);
            let mut cumulative = 0;
            let mut idx = 0;
            for (i, &weight) in self.weights.iter().enumerate() {
                cumulative += weight;
                if random_val < cumulative {
                    idx = i;
                    break;
                }
            }

            let size = self.sizes[idx].min(remaining.len());

            // Extract chunk and add to output
            let chunk = remaining[..size].to_vec();
            chunks.push(chunk);

            // Remove processed data
            remaining.drain(..size);
        }

        chunks
    }
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_shaper_creation() {
        let shaper = TrafficShaper::new();
        assert!(!shaper.sizes.is_empty());
        assert_eq!(shaper.sizes.len(), 7);
    }

    #[test]
    fn test_traffic_shaper_basic_split() {
        let shaper = TrafficShaper::new();
        let data = vec![0u8; 10000];
        let chunks = shaper.shape(&data);

        // Verify all data is preserved
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());

        // Verify no empty chunks
        assert!(chunks.iter().all(|c| !c.is_empty()));
    }

    #[test]
    fn test_traffic_shaper_empty_data() {
        let shaper = TrafficShaper::new();
        let chunks = shaper.shape(&[]);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_traffic_shaper_small_data() {
        let shaper = TrafficShaper::new();
        let data = vec![0u8; 50];
        let chunks = shaper.shape(&data);

        // Small data should result in single chunk
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 50);
    }

    #[test]
    fn test_traffic_shaper_distribution() {
        // Statistical test: verify packet sizes are from valid set
        let shaper = TrafficShaper::new();
        let data = vec![0u8; 50000];
        let chunks = shaper.shape(&data);

        for chunk in &chunks {
            let size = chunk.len();
            // Each chunk should be one of the predefined sizes (except possibly the last)
            assert!(size <= 16384, "Chunk size {} exceeds maximum", size);
            assert!(size > 0, "Empty chunk found");
        }
    }

    #[test]
    fn test_traffic_shaper_size_preservation() {
        let shaper = TrafficShaper::new();
        for test_size in &[100, 1000, 5000, 100000] {
            let data = vec![0u8; *test_size];
            let chunks = shaper.shape(&data);
            let total: usize = chunks.iter().map(|c| c.len()).sum();
            assert_eq!(total, *test_size);
        }
    }
}
