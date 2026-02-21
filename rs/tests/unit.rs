// Unit tests extracted from inline #[cfg(test)] modules
// This file includes all unit test modules from rs/tests/unit/

mod unit {
    pub mod cli;
    pub mod constant_time_and_kdf;
    pub mod constants;
    pub mod credential_store;
    pub mod crypto;
    pub mod errors;
    pub mod formats;
    pub mod keys;
    pub mod security_hardening;
    pub mod signature;
    pub mod validation;
    pub mod wordlist;

    pub mod ops {
        pub mod change;
        pub mod file_utils;
        pub mod generate;
        pub mod helpers;
        pub mod inspect;
        pub mod recreate;
        pub mod sign;
        pub mod verify;
    }
}
