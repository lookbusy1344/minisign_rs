// Unit tests extracted from inline #[cfg(test)] modules
// This file includes all unit test modules from rs/tests/unit/

mod unit {
    pub mod cli;
    pub mod constants;
    pub mod crypto;
    pub mod errors;
    pub mod formats;
    pub mod hw_slot;
    pub mod keys;
    pub mod phase1_security_tests;
    pub mod phase2_h5_only;
    pub mod phase2_security_tests;
    pub mod signature;
    pub mod validation;
    pub mod wordlist;

    pub mod ops {
        pub mod change;
        pub mod generate;
        pub mod inspect;
        pub mod recreate;
        pub mod sign;
        pub mod verify;
    }
}
