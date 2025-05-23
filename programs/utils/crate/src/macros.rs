/// Copies a byte slice into `buf` at the current `offset`, then increments `offset` by the slice length.
///
/// # Example
/// ```rust
/// let mut buf = [0u8; 80];
/// let mut offset = 0;
///
/// // Write a 1-byte instruction tag
/// buf[offset] = 11;
/// offset += 1;
///
/// // Write an 8-byte little-endian lamports amount
/// push_le!(buf, offset, lamports);
///
/// // Write seed length (u64 LE) and seed bytes
/// push_le!(buf, offset, seed.len() as u64);
/// push_bytes!(buf, offset, seed);
///
/// // Write a 32-byte owner public key
/// push_bytes!(buf, offset, owner.as_ref());
/// ```
#[macro_export]
macro_rules! push_bytes {
    ($buf:expr, $off:ident, $val:expr) => {
        {
            let bytes: &[u8] = $val.as_ref();
            let len = bytes.len();
            $buf[$off..$off + len].copy_from_slice(bytes);
            $off += len;
        }
    };
}

/// Push a primitive's little-endian bytes into a buffer at offset, then advance the offset.
#[macro_export]
macro_rules! push_le {
    ($buf:expr, $off:ident, $val:expr) => {
        {
            let bytes = $val.to_le_bytes();
            let len = bytes.len();
            $buf[$off..$off + len].copy_from_slice(&bytes);
            $off += len;
        }
    };
}