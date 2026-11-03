use anyhow::Context as _;
use std::env::VarError;

pub fn from_env() -> anyhow::Result<u16> {
    parse(std::env::var("ADMIN_PORT"))
}

fn parse(value: Result<String, VarError>) -> anyhow::Result<u16> {
    match value {
        Ok(value) => value
            .parse()
            .context("ADMIN_PORT must be a port number from 0 to 65535"),
        Err(VarError::NotPresent) => Ok(3001),
        Err(VarError::NotUnicode(_)) => anyhow::bail!("ADMIN_PORT must contain valid UTF-8"),
    }
}

#[cfg(test)]
mod tests;
