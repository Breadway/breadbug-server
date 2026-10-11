//! breadbug-server: public intake for breadbug reports, plus the admin side.
//!
//! Everything arriving on the public listener is hostile input. See
//! `docs/threat-model.md`.

pub mod app;
pub mod config;
pub mod crypto;
pub mod db;
pub mod ratelimit;
pub mod rescrub;
pub mod schema;
