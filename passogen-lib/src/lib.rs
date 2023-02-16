mod entropy;
/// Error indicating failure to generate password, due to insufficient entropy.
pub use entropy::NotEnoughEntropy;

mod generators;
mod util;

/// Configurations for different password generation schemes.
pub mod config;
use config::Config;

/// Generate password.
pub fn generate(
    master_password: &[u8],
    domain: &[u8],
    username: &[u8],
    counter: u64,
    config: &Config,
) -> String {
    match *config {
        Config::RandomV1(ref config) => {
            generators::random::v1::generate(master_password, domain, username, counter, config)
        }
    }
}
