// Unit tests extracted from inline #[cfg(test)] modules
// This file includes all unit test modules from rs/tests/unit/

mod unit {
    pub mod cli;
    pub mod constants;
    pub mod credential_store;
    pub mod crypto;
    pub mod errors;
    pub mod formats;
    pub mod keys;
    pub mod signature;
    pub mod validation;
    pub mod wordlist;

    pub mod ops {
        pub mod change;
        pub mod inspect;
        pub mod recreate;
        pub mod sign;
        pub mod verify;
    }
}
