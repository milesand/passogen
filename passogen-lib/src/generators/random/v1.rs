use crate::util::{make_salt, LOWERCASES, NUMBERS, UPPERCASES};
use crate::{entropy::v1::Entropy, NotEnoughEntropy};
use argon2::{Algorithm, Argon2, Params, Version};

pub struct Config {
    pub max_length: usize,
    pub min_length: usize,

    pub min_lower: usize,
    pub min_upper: usize,
    pub min_number: usize,
    pub min_special: usize,
    pub special_chars: Vec<char>,
}

/*
fn default_special_chars() -> Vec<u8> {
    vec![b'~', b'!', b'#', b'%', b'^', b'*']
}
*/

impl Config {
    fn check(&self) -> Result<(), ()> {
        if self.min_length > self.max_length {
            return Err(());
        }
        if self.min_lower + self.min_upper + self.min_number + self.min_special > self.max_length {
            return Err(());
        }
        if self.min_special != 0 && self.special_chars.is_empty() {
            return Err(());
        }
        Ok(())
    }
}

pub fn generate(
    master_password: &[u8],
    domain: &[u8],
    username: &[u8],
    counter: u64,
    config: &Config,
) -> String {
    // TODO: handle this more gracefully. Maybe make Config's fields private and supply a Builder?
    config.check().expect("Invalid config");
    let salt = make_salt(domain, username, counter);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(4096, 3, 1, None).unwrap(),
    );
    let mut entropy_len = 4;
    let mut entropy_buf = vec![0; entropy_len];
    loop {
        // PANIC: hash_password_into can return `Err` if:
        // - Output is too short(less than 4 bytes): We can ignore this since we start at 4 bytes.
        // - Output is too long(more than 0xFFFFFFFF bytes): Possible, but this requires 31 failures which seems unlikely unless the requested password length is really long.
        // - Master password is too long(more than 0xFFFFFFFF bytes): Possible and entirely dependent on input. I *think* nobody's gonna use master password longer than 0xFFFFFFFF bytes?
        // - Salt is too short(less than 8 bytes): Our salt generation scheme gurantees at least 9 bytes.
        // - Salt is too long(more than 0xFFFFFFFF bytes): Again possible and dependent on input. Still requires domain + username to be longer than approx. 0xFFFFFFFF bytes.
        // TODO: handle possible panic conditions(though unlikely).
        argon2
            .hash_password_into(master_password, &salt, &mut entropy_buf)
            .expect("Argon2 failed");
        let mut entropy = Entropy::new(entropy_buf);
        if let Ok(password) = generate_from_entropy(&mut entropy, config) {
            break password;
        }
        entropy_buf = entropy.into_inner().0;
        // PANIC: Too many failures make `entropy_len` overflow `usize`.
        // TODO: handle this.
        entropy_len = entropy_len
            .checked_mul(2)
            .expect("Entropy buffer length overflowed");
        entropy_buf.resize(entropy_len, 0);
    }
}

fn generate_from_entropy(
    entropy: &mut Entropy,
    config: &Config,
) -> Result<String, NotEnoughEntropy> {
    let length = {
        let min_length = config
            .min_length
            .max(config.min_lower + config.min_upper + config.min_number + config.min_special);
        let diff = config.max_length - config.min_length;
        config.min_length + entropy.get_usize_with_max(diff)?
    };
    let mut char_pos_pairs = Vec::new();
    let mut indices: Vec<_> = (0..length).collect();
    let special_chars = {
        let mut special_chars = config.special_chars.clone();
        special_chars.sort_unstable();
        special_chars.dedup();
        special_chars
    };
    let min_and_char_set_pairs = [
        (config.min_lower, LOWERCASES),
        (config.min_upper, UPPERCASES),
        (config.min_number, NUMBERS),
        (config.min_special, &special_chars),
    ];
    for (min, char_set) in min_and_char_set_pairs {
        for _ in 0..min {
            let i = entropy.get_usize_with_max(indices.len() - 1)?;
            let pos = indices.swap_remove(i);
            let ch = char_set[entropy.get_usize_with_max(char_set.len() - 1)?];
            char_pos_pairs.push((ch, pos));
        }
    }
    char_pos_pairs.sort_unstable_by(|&(_, pos_a), &(_, pos_b)| pos_a.cmp(&pos_b).reverse());
    let char_set = Vec::from_iter(
        LOWERCASES
            .iter()
            .copied()
            .chain(UPPERCASES.iter().copied())
            .chain(NUMBERS.iter().copied())
            .chain(special_chars.iter().copied()),
    );
    let mut password = String::new();
    for idx in 0..length {
        if let Some(&(ch, pos)) = char_pos_pairs.last() {
            if idx == pos {
                password.push(ch);
                char_pos_pairs.pop();
                continue;
            }
        }
        let ch = char_set[entropy.get_usize_with_max(char_set.len() - 1)?];
        password.push(ch);
    }
    Ok(password)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn value_stability() {
        let config = Config {
            max_length: 16,
            min_length: 16,
            min_lower: 1,
            min_upper: 1,
            min_number: 1,
            min_special: 1,
            special_chars: vec!['~', '!', '@', '#', '$', '%', '^'],
        };
        let test_cases = [
            (
                "hunter2",
                "some IRC network",
                "AzureDiamond",
                0,
                "@1nC^AMR2ahW^YWB",
            ),
            (
                "hunter2",
                "some IRC network",
                "AzureDiamond",
                1,
                "y#WC0tV~pNSdMHGY",
            ),
            (
                "hunter2",
                "some IRC network",
                "AzureDiamond",
                2,
                "D8l39IK%6~KuUd#l",
            ),
            ("123456", "example.com", "qwerty", 0, "b2~RMwE5y9xkc0QV"),
            ("123456", "example.com", "qwerty", 1, "^RVh8A^za4fzIApK"),
            ("123456", "example.com", "qwerty", 2, "pnHMamQ%gD38ZEOw"),
        ];
        for (master_password, domain, username, counter, expected) in test_cases.iter().copied() {
            let password = generate(
                master_password.as_bytes(),
                domain.as_bytes(),
                username.as_bytes(),
                counter,
                &config,
            );
            assert_eq!(password, expected);
        }
    }
}
