pub struct AccSha256 {
    hash: [u32; 8],
}

impl Default for AccSha256 {
    fn default() -> Self {
        Self {
            hash: [
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
                0x5BE0CD19,
            ],
        }
    }
}
impl From<&str> for AccSha256 {
    fn from(value: &str) -> Self {
        let mut acc = Self::default();
        acc.add(value.as_bytes());
        acc
    }
}

#[inline(always)]
fn rl(a: u32, n: u32) -> u32 {
    a << (n & 31)
}

impl AccSha256 {
    pub fn add(&mut self, text: &[u8]) {
        let l = text.len() << 3;
        let mut m = vec![0u32; (((l + 64) >> 9) << 4) + 16];

        for i in 0..text.len() {
            m[i >> 2] |= rl(text[i] as u32, (24 - ((i << 3) & 31)) as u32);
        }

        m[l >> 5] |= 0x80 << (24 - l % 32);

        m[(((l + 64) >> 9) << 4) + 15] = l as u32;

        let mut w = vec![0u32; 64];

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hash;
        for i in (0..m.len()).step_by(16) {
            for j in 0..64 {
                if j < 16 {
                    w[j] = m[j + i];
                } else {
                    let gamma0x = w[j - 15];
                    let gamma1x = w[j - 2];
                    let gamma0 = (rl(gamma0x, 25) | (gamma0x >> 7))
                        ^ (rl(gamma0x, 14) | (gamma0x >> 18))
                        ^ (gamma0x >> 3);

                    let gamma1 = (rl(gamma1x, 15) | (gamma1x >> 17))
                        ^ (rl(gamma1x, 13) | (gamma1x >> 19))
                        ^ (gamma1x >> 10);

                    w[j] = gamma0
                        .wrapping_add(w[j - 7])
                        .wrapping_add(gamma1)
                        .wrapping_add(w[j - 16]);
                }

                let ch = e & f ^ !e & g;
                let maj = a & b ^ a & c ^ b & c;

                let sigma0 = (rl(a, 30) | (a >> 2)) ^ a.rotate_right(13) ^ a.rotate_left(10);
                let sigma1 = e.rotate_right(6) ^ (rl(e, 21) | (e >> 11)) ^ e.rotate_left(7);

                let t1 = h
                    .wrapping_add(sigma1)
                    .wrapping_add(ch)
                    .wrapping_add(K[j])
                    .wrapping_add(w[j]);
                let t2 = sigma0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            a = self.hash[0].wrapping_add(a);
            self.hash[0] = a;
            b = self.hash[1].wrapping_add(b);
            self.hash[1] = b;
            c = self.hash[2].wrapping_add(c);
            self.hash[2] = c;
            d = self.hash[3].wrapping_add(d);
            self.hash[3] = d;
            e = self.hash[4].wrapping_add(e);
            self.hash[4] = e;
            f = self.hash[5].wrapping_add(f);
            self.hash[5] = f;
            g = self.hash[6].wrapping_add(g);
            self.hash[6] = g;
            h = self.hash[7].wrapping_add(h);
            self.hash[7] = h;
        }
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        self.hash
            .iter()
            .for_each(|v| hex.push_str(format!("{:08x}", v).as_str()));
        hex
    }

    pub fn to_id(&self) -> String {
        let mut id = String::with_capacity(17);
        let mut count = 17;
        self.hash.iter().find(|v| {
            let v = **v;
            for i in 0..4 {
                id.push(CHARS[(((v >> (i << 3)) & 0xff) % 62) as usize] as char);
                count -= 1;
                if count == 0 {
                    return true;
                }
            }
            false
        });
        id
    }
}

const CHARS: &[u8] = b"1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

const K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

#[cfg(test)]
#[path = "sha_test.rs"]
mod test;
