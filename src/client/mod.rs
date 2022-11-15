#[allow(clippy::module_inception)]
pub(crate) mod client;
mod client_auth;
mod client_kex;

pub(crate) use client::Client;
