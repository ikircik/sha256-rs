// constants from section 4.2.2 in https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug)]
pub struct Sha256 {
    state: [u32; 8],
    bit_len: usize,
    data: [u8; 64],
    data_len: usize,
}

impl Sha256 {
    pub fn new(state: Option<[u32; 8]>) -> Self {
        Self {
            // initial state from section 5.3.2 in https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf
            state: state.unwrap_or([
                0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32, 0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
            ]),
            bit_len: 0,
            data: [0u8; 64],
            data_len: 0,
        }
    }

    pub fn update(state: &mut [u32; 8], data: &[u8; 64]) {
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        let mut m = [0u32; 64];

        let mut j = 0;
        for i in 0..16 {
            m[i] = ((data[j] as u32) << 24) | ((data[j + 1] as u32) << 16) | ((data[j + 2] as u32) << 8) | (data[j + 3] as u32);
            j = j + 4;
        }

        for i in 16..64 {
            let sig0 = m[i - 15].rotate_right(7) ^ m[i - 15].rotate_right(18) ^ (m[i - 15] >> 3);
            let sig1 = m[i - 2].rotate_right(17) ^ m[i - 2].rotate_right(19) ^ (m[i - 2] >> 10);
            m[i] = sig1.wrapping_add(m[i - 7]).wrapping_add(sig0).wrapping_add(m[i - 16]);
        }

        for i in 0..64 {
            let ep0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let ep1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);

            let t1 = h.wrapping_add(ep1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(m[i]);
            let t2 = ep0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn append(&mut self, data: &[u8]) {
        for i in 0..data.len() {
            self.data[self.data_len] = data[i];
            self.data_len = self.data_len + 1;

            if self.data_len == 64 {
                Self::update(&mut self.state, &self.data);
                self.bit_len = self.bit_len + 512;
                self.data_len = 0;
            }
        }
    }

    pub fn r#final(&mut self) -> [u8; 32] {
        let data_bits = self.bit_len + self.data_len * 8;
        let mut data = [0u8; 72];
        data[0] = 128;

        let offset = if self.data_len < 56 {
            56 - self.data_len
        } else {
            120 - self.data_len
        };

        data[offset..offset + 8].copy_from_slice(&data_bits.to_be_bytes());
        self.append(&data[0..offset + 8]);

        let mut output = [0u8; 32];
        for i in 0..8 {
            let state_be_bytes = self.state[i].to_be_bytes();
            output[i * 4] = state_be_bytes[0];
            output[i * 4 + 1] = state_be_bytes[1];
            output[i * 4 + 2] = state_be_bytes[2];
            output[i * 4 + 3] = state_be_bytes[3];
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_test() {
        let var = 4;
        assert_eq!(var, 4);
    }
}
