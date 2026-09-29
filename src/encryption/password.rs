use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ByteWriter;

/// A password used for password protected, encrypted files.
///
/// Use [`Password::empty()`] to create an empty password when no
/// password is used.
///
/// You can convert strings easily into password using the Into/From traits:
///
/// ```rust
/// use sevenz_rust2::Password;
///
/// let password: Password = "a password string".into();
/// ```
///
/// The password bytes are wiped when a [`Password`] is dropped, and its [`Debug`](fmt::Debug)
/// output never contains them.
#[derive(Default, Clone, PartialEq)]
pub struct Password(Vec<u8>);

impl Zeroize for Password {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Password {}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}

impl Password {
    /// Creates a new [`Password`] from the given password string.
    ///
    /// Internally a password string is encoded as UTF-16.
    pub fn new(password: &str) -> Self {
        Self::from(password)
    }

    /// Creates a new [`Password`] from the given raw bytes.
    pub fn from_raw(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Creates an empty password.
    pub fn empty() -> Self {
        Self(Default::default())
    }

    /// Returns the byte representation of the password.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns `true` if the password is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        // Every UTF-16 code unit comes from at least one UTF-8 byte, so `s.len() * 2` bytes
        // always suffice: the buffer never reallocates, leaving no unwiped copy behind.
        let mut result = Vec::with_capacity(s.len() * 2);
        let utf16 = s.encode_utf16();
        for u in utf16 {
            let _ = result.write_u16(u);
        }
        Self(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_password() {
        let password = Password::from("hunter2");
        let debug = format!("{password:?}");
        assert_eq!(debug, "Password([REDACTED])");
    }

    #[test]
    fn zeroize_clears_the_password() {
        let mut password = Password::from("hunter2");
        password.zeroize();
        assert!(password.is_empty());
    }

    #[test]
    fn from_str_does_not_reallocate() {
        for s in ["", "a", "hunter2", "pässwörd", "密码", "🔑🔑"] {
            let password = Password::from(s);
            assert_eq!(password.0.capacity(), s.len() * 2);
        }
    }
}
