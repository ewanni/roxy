// Obfuscation module for DPI bypass
//
// Provides traffic shaping, padding, and timing obfuscation to evade
// deep packet inspection by mimicking HTTPS-like traffic patterns.

pub mod traffic_shaper;
pub mod padding;
pub mod timing;

pub use traffic_shaper::TrafficShaper;
pub use padding::PaddingStrategy;
pub use timing::TimingObfuscator;
