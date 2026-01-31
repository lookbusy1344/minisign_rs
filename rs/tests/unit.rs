// Unit tests extracted from inline #[cfg(test)] modules
// This file includes all unit test modules from rs/tests/unit/

mod unit {
    pub mod crypto;
    pub mod keys;
    pub mod signature;

    pub mod ops {
        pub mod change;
        pub mod generate;
        pub mod inspect;
        pub mod recreate;
        pub mod sign;
        pub mod verify;
    }
}
