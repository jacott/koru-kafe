use super::sha::AccSha256;

pub struct Random {
    sha256: AccSha256,
}

impl Random {
    pub fn new(seeds: &[&[u8]]) -> Self {
        let mut sha256 = AccSha256::default();
        let f = seeds.iter().map(|v| v.iter().copied());
        let f: Vec<u8> = f.flatten().collect();
        sha256.add(&f[..]);

        Self { sha256 }
    }

    pub fn id(&mut self) -> String {
        self.sha256.add(b"1");
        self.sha256.to_id()
    }
}

#[cfg(test)]
#[path = "rand_test.rs"]
mod test;
