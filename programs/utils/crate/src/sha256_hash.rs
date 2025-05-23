#[cfg(any(feature = "sha256_hash", not(target_os = "solana")))]
use sha2::{Digest, Sha256};
extern crate sha2;
#[cfg(any(feature = "sha256_hash", not(target_os = "solana")))]
#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

/// Size of a hash in bytes.
pub const HASH_BYTES: usize = 32;

pub struct Hash(pub(crate) [u8; HASH_BYTES]);

impl From<[u8; HASH_BYTES]> for Hash {
    fn from(from: [u8; 32]) -> Self {
        Self(from)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(any(feature = "sha256_hash", not(target_os = "solana")))]
impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        let bytes: [u8; HASH_BYTES] = self.hasher.finalize().into();
        bytes.into()
    }
}

#[cfg(target_os = "solana")]
use pinocchio::syscalls::sol_sha256;

/// Return a Sha256 hash for the given data.
pub fn hashv(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Hasher::default();
        hasher.hashv(vals);
        hasher.result()
    }
    // Call via a system call to perform the calculation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; HASH_BYTES];
        unsafe {
            sol_sha256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

/// Return a Sha256 hash for the given data.
pub fn hash(val: &[u8]) -> Hash {
    hashv(&[val])
}

/// Return the hash of the given hash extended with the given value.
pub fn extend_and_hash(id: &Hash, val: &[u8]) -> Hash {
    let mut hash_data = id.as_ref().to_vec();
    hash_data.extend_from_slice(val);
    hash(&hash_data)
}


impl Hash {
    pub const fn new_from_array(hash_array: [u8; HASH_BYTES]) -> Self {
        Self(hash_array)
    }

    pub fn to_bytes(self) -> [u8; HASH_BYTES] {
        self.0
    }
}