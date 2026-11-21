//! Uwierzytelnianie DScan. Na tym etapie: hasła (argon2id) i walidacja loginów,
//! potrzebne do `dscan user create-admin`. Sesje i RBAC dojdą w zadaniach A2/A3.

mod error;
mod password;
mod username;

pub use error::AuthError;
pub use password::{
    MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, hash_password, validate_password_strength, verify_password,
};
pub use username::{MAX_USERNAME_LEN, MIN_USERNAME_LEN, validate_username};
