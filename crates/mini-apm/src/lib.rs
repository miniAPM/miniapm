// The unit-test harness is an executable that calls none of the public API
#![cfg_attr(test, allow(dead_code_pub_in_binary))]

pub mod api;
pub mod cli;
pub mod config;
pub mod db;
pub mod jobs;
pub mod models;
pub mod repair;
pub mod self_monitor;
pub mod server;
pub mod telemetry;
pub mod time;

pub use db::DbPool;
pub use telemetry::init_tracing;
