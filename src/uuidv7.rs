use std::{
    cmp::min,
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{Rng, rng};

#[cfg(test)]
#[path = "uuidv7_test.rs"]
mod test;

pub(crate) const CHARS: &[u8] = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~";
pub const B64_MAP: [u8; 256] = {
    let mut map = [0u8; 256];
    let mut i = 0;
    while i < 64 {
        map[CHARS[i] as usize] = i as u8;
        i += 1;
    }
    map
};

pub(crate) fn char_to_u6(b: u8) -> u8 {
    B64_MAP[b as usize]
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuidv7(u128);
impl Uuidv7 {
    pub fn time_and_rand<R: Into<u128>>(time: SystemTime, rand: R) -> Self {
        let time = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let ms: u128 = time.as_millis();
        let nanos_fraction = time.as_nanos() - (ms * 1_000_000);
        let scaled_fraction = (nanos_fraction * 4096 + 500_000) / 1_000_000;
        let rand: u128 = rand.into();

        Self(
            ((ms & 0xFFFF_FFFF_FFFF) << 80 | ((7 << 12) | (scaled_fraction & 0xfff)) << 64)
                | (2 << 62)
                | (rand & 0x3FFF_FFFF_FFFF_FFFF),
        )
    }

    pub fn random() -> Self {
        let mut rng = rng();
        Self::time_and_rand(SystemTime::now(), rng.next_u64())
    }

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub(crate) fn write_str(
        f: &mut std::fmt::Formatter<'_>,
        mut val: u128,
    ) -> Result<(), std::fmt::Error> {
        for _ in 0..22 {
            // Grab the top 6 bits (128 - 6 = 122)
            let idx = (val >> 122) as usize;

            // Write the character to the formatter
            write!(f, "{}", CHARS[idx] as char)?;

            // Shift the entire block left by 6 bits
            val <<= 6;
        }

        Ok(())
    }
}
impl Display for Uuidv7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return Uuidv7::write_str(f, self.0);
    }
}

impl From<Uuidv7> for u128 {
    fn from(value: Uuidv7) -> Self {
        value.0
    }
}
impl From<u128> for Uuidv7 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}
impl From<&str> for Uuidv7 {
    fn from(value: &str) -> Self {
        Uuidv7::from(value.as_bytes())
    }
}
impl From<&[u8]> for Uuidv7 {
    fn from(bytes: &[u8]) -> Self {
        let mut val: u128 = 0;

        let len = min(21, bytes.len());

        // Process the first 21 characters (21 * 6 = 126 bits)
        for b in bytes.iter().take(len) {
            let b = char_to_u6(*b) as u128;
            val = (val << 6) | b;
        }

        if len < bytes.len() {
            // 2. Process the 22nd character
            // We have 126 bits. We need 2 more to reach 128.
            // The 22nd character 'b' has 6 bits.
            // We take the top 2 bits of 'b' and discard the bottom 4.
            let b_last = char_to_u6(bytes[min(21, bytes.len() - 1)]) as u128;

            // Shift val left by 2, and add the high 2 bits of b_last (b_last >> 4)
            val = (val << 2) | (b_last >> 4);
        } else {
            val <<= 2 + 6 * (bytes.len() - len);
        }

        Self(val)
    }
}
