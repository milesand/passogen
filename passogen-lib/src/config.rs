/// All available configs in a single enum.
#[non_exhaustive]
pub enum Config {
    RandomV1(RandomV1Config),
}

/// Config for generation scheme Random Version 1.
pub use crate::generators::random::v1::Config as RandomV1Config;
