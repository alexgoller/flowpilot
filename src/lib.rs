//! Rust reimplementation of Illumio FlowLink 2.0.1-2. User-visible behaviour and every difference
//! from FlowLink are described in `docs/`.

pub mod aggregator;
pub mod cli;
pub mod config;
pub mod connectors;
pub mod env_config;
pub mod flow;
pub mod instance_id;
pub mod install;
pub mod log;
pub mod metrics;
pub mod parsers;
pub mod proto;
pub mod reported_ips;
pub mod secrets;
pub mod spool;
pub mod stats;
pub mod unmanaged;
pub mod uploader;
