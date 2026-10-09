//! breadbug-server: public intake for breadbug reports, plus the admin side.
//!
//! Everything arriving on the public listener is hostile input. See
//! `docs/threat-model.md`.

pub mod admin;
pub mod app;
pub mod board;
pub mod cluster;
pub mod config;
pub mod crypto;
pub mod db;
pub mod embed;
pub mod fingerprint;
pub mod lifecycle;
pub mod ratelimit;
pub mod rescrub;
pub mod schema;
pub mod symbolicate;
pub mod triage;

pub fn symbol_worker_entry() -> bool {
    symbolicate::worker_main()
}
