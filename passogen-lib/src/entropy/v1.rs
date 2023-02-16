use super::NotEnoughEntropy;

#[derive(Debug, Clone)]
pub struct Entropy {
    bytes: Vec<u8>,
    // Solid value of reclaimed entropy, that couldn't be pushed directly back into the byte array.
    reclaimed: u64,
    // Upper bound of `reclaimed`, or rather, the amount of entropy stored in `reclaimed`.
    // This value should equal 2 ^ (amount of entropy, in bits) - 1.
    reclaimed_upper_bound: u64,
}

// Chooses one value in 0..=max using given entropy.
// Returns Ok((chosen value, new entropy value, new entropy amount)) on success,
// Err(()) on failure due to non-uniformness.
// Panics if entropy_amount < max, or entropy_amount < entropy_value.
fn choose_1_with_max(
    max: u64,
    entropy_value: u64,
    entropy_amount: u64,
) -> Result<(u64, u64, u64), ()> {
    assert!(max <= entropy_amount);
    assert!(entropy_value <= entropy_amount);

    if max == u64::MAX {
        // since max <= entropy_amount, entropy_amount == u64::MAX
        return Ok((entropy_value, 0, 0));
    }

    let cases = max + 1;

    let q = entropy_value / cases;
    let r = entropy_value % cases;
    let amount_q = entropy_amount / cases;
    let amount_r = entropy_amount % cases;

    if amount_r != max && amount_q == q {
        return Err(());
    }
    let choice = r;
    let new_entropy_value = q;
    let new_entropy_amount = if amount_r == max {
        amount_q
    } else {
        amount_q - 1
    };
    Ok((choice, new_entropy_value, new_entropy_amount))
}

impl Entropy {
    pub fn new(bytes: Vec<u8>) -> Self {
        Entropy {
            bytes,
            reclaimed: 0,
            reclaimed_upper_bound: 0,
        }
    }

    pub fn into_inner(self) -> (Vec<u8>, u64, u64) {
        let Entropy {
            bytes,
            reclaimed,
            reclaimed_upper_bound,
        } = self;
        (bytes, reclaimed, reclaimed_upper_bound)
    }

    pub fn put_back_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn put_back_u64(&mut self, value: u64) {
        for byte in value.to_be_bytes() {
            self.bytes.push(byte);
        }
    }

    // Reclaim entropy from sampled-but-not-used part of some calculation.
    // Suppose we needed to randomly choose 1 out of 3. We can basically sample a byte,
    // and calculate modulo 3 to make that choice, with some additional steps to make the choice
    // uniform. But what we actually need is just log2(3) bits(approx. 1.585 bits), not 8 bits,
    // and we're throwing away the approx. 6.415 bits we didn't use.
    // That 6.415 bits correspond to the quotient of division-by-3, plus some states(in this case, when byte is 255)
    // we must throw away to make sampling uniform. We can't really reclaim entropy in the latter case(I think),
    // but we can take the quotient and reclaim it; In this case, the quotient would be a value between 0 and 84,
    // So that's like choosing 1 out of 85 cases.
    // So to reclaim that, one would call this function with value = (actual quotient), and upper_bound = 85.
    fn put_back_u64_with_upper_bound(&mut self, value: u64, upper_bound: u64) {
        assert!(value <= upper_bound);
        if upper_bound == u64::MAX {
            self.put_back_u64(value);
            return;
        }

        // While probably very unlikely, it is possible for reclaimed-entropy to build up in `reclaimed`
        // without getting reclaimed into the byte array. In that case, attempt to calculate `new_rub`
        // would overflow.
        let new_rub_opt = (self.reclaimed_upper_bound)
            .checked_mul(upper_bound + 1)
            .and_then(|x| x.checked_add(upper_bound));

        let (mut new_r, mut new_rub) = if let Some(new_rub) = new_rub_opt {
            // No overflow; since self.reclaimed <= self.reclaimed_upper_bound,
            // and value <= upper_bound, the following should not overflow.
            (self.reclaimed * (upper_bound + 1) + value, new_rub)
        } else {
            // Overflow happened, so spill `reclaim` and start anew.
            (value, upper_bound)
        };

        // Try to reclaim the lowest byte(s) of `reclaimed` into the byte array.
        // Assuming reclaimed entropy comes from random sampling from uniform distribution,
        // `new_r` can be considered a result of random sampling between 0..=`new_rub`,
        // So the lowest byte is uniformly random-ish, but not entirely; It's slightly more
        // biased towards the lower values, because at the highest end, there are extra values
        // for 0..=(new_rub % 256). To make sure this is uniform:
        // 1. If new_rub % 256 == 255, then these 'extra values' don't cause any bias, so it's uniform.
        // 2. If `new_r` is at the highest end: that is, new_r / 256 == new_rub / 256 (integer division),
        //    then the `new_r`'s lowest byte is biased and should not be reclaimed.
        while new_rub & 255 == 255 || new_r >> 8 != new_rub >> 8 {
            let lowest_byte = (new_r & 255) as u8; // 0 <= new_r & 255 <= 255 (math), so fine
            self.bytes.push(lowest_byte);
            new_r >>= 8;
            new_rub >>= 8;
        }
        self.reclaimed = new_r;
        self.reclaimed_upper_bound = new_rub;
    }

    pub fn get_u8_with_max(&mut self, max: u8) -> Result<u8, NotEnoughEntropy> {
        self.get_u64_with_max(u64::from(max)).map(|x| x as u8)
    }

    pub fn get_u32_with_max(&mut self, max: u32) -> Result<u32, NotEnoughEntropy> {
        self.get_u64_with_max(u64::from(max)).map(|x| x as u32)
    }

    pub fn get_u64_with_max(&mut self, max: u64) -> Result<u64, NotEnoughEntropy> {
        if max == 0 {
            return Ok(0);
        }

        if self.reclaimed_upper_bound >= max {
            if let Ok((choice, ev, ea)) =
                choose_1_with_max(max, self.reclaimed, self.reclaimed_upper_bound)
            {
                self.reclaimed = ev;
                self.reclaimed_upper_bound = ea;
                return Ok(choice);
            }
        }

        if max == u64::MAX {
            let mut bytes = [0; 8];
            for byte_ref in bytes.iter_mut() {
                *byte_ref = self.bytes.pop().ok_or(NotEnoughEntropy)?;
            }
            return Ok(u64::from_be_bytes(bytes));
        }

        let mut buf: u64 = 0;
        let mut buf_max: u64 = 0;
        loop {
            let byte = u64::from(self.bytes.pop().ok_or(NotEnoughEntropy)?);
            buf = buf << 8 | byte;
            buf_max = buf_max << 8 | 255;
            if buf_max < max {
                continue;
            }

            if let Ok((choice, ev, ea)) = choose_1_with_max(max, buf, buf_max) {
                self.put_back_u64_with_upper_bound(ev, ea);
                return Ok(choice);
            }
        }
    }

    pub fn get_usize_with_max(&mut self, max: usize) -> Result<usize, NotEnoughEntropy> {
        // PANIC: If target platform happens to have `usize` that's larger than `u64`, and `max` overflows `u64`.
        self.get_u64_with_max(u64::try_from(max).expect("`usize` does not fit `u64`"))
            .map(|x| x as usize)
    }
}

#[cfg(test)]
mod test {
    use super::Entropy;

    #[test]
    fn get_8_bytes() {
        let mut entropy = Entropy::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        for i in 0..8 {
            assert!(
                entropy.get_u8_with_max(255).is_ok(),
                "Iteration {} returned Err",
                i
            );
        }
        assert!(
            entropy.get_u8_with_max(255).is_err(),
            "Last iteration returned Ok"
        );
    }

    #[test]
    fn choose_1in3_from_a_byte() {
        // A byte is 8 bits, and a 1-in-3 choice consumes log2(3) bits, approximately 1.585 bits.
        // So *theoretically* we can make 5 1-in-3 choices using a byte, in practice we throw away some
        // entropy so 4 choices seem fine.
        //
        // For higher bytes, we have to reject some entropy-values entirely, for uniform sampling.
        // Under current implementation(2023-02-04), this should first happen at byte = 243,
        // Since:
        // * After first choice and reclamation, we have `reclaim` = 243 / 3 = 81, `reclaim_upper_bound` = (255 + 1) / 3 - 1 = 84.
        // * After second choice, we have `reclaim` = 81 / 3 = 27, `reclaim_upper_bound` = (84 + 1) / 3 - 1 = 27.
        // * (27 + 1) % 3 = 1, so we can only use `reclaim` values 0 ~ 27-1 (inclusive) for uniformity. We have `reclaim` = 27,
        //   so we have to stop here.
        // ... And no such thing happens for lower entropy-value, due to a coincidence that 256 / 3 / 3 / 3 = 9
        // and 256 / 3 / 3 / 3 / 3 = 3 are powers of 3.
        // So in retrospect, the idea behind this test doesn't handle those throw-away-whole-entropy cases very well,
        // and the test itself kind of works only because 3 is a magic number.
        'test_case: for byte in 0..=242 {
            let mut entropy = Entropy::new(vec![byte]);
            for i in 0..6 {
                if entropy.get_u8_with_max(2).is_err() {
                    if 4 <= i && i <= 5 {
                        continue 'test_case;
                    }
                    panic!("entropy.get_u8_with_max(3) returned Err(_) on iteration {} (Less than 4 choices made)", i + 1);
                }
            }
            if entropy.get_u8_with_max(2).is_ok() {
                panic!("entropy.get_u8_with_max(3) returned Ok(_) on iteration 6, byte = {} (More than 5 choices made)", byte);
            }
        }
    }

    #[test]
    fn value_stability() {
        let mut entropy = Entropy::new("Hello, world!".as_bytes().to_owned());
        let expected_values = [
            33, 14, 22, 12, 28, 25, 12, 33, 32, 1, 8, 25, 22, 37, 22, 15, 29, 18,
        ];
        for expected_value in expected_values {
            assert_eq!(Ok(expected_value), entropy.get_u8_with_max(42));
        }
        assert!(entropy.get_u8_with_max(42).is_err());
    }
}
