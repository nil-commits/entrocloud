//! EntroCloud v1.0 CLI library surface exposing testable parser, `Zeroizing` secret readers,
//! sibling `entrocloudd` auto-spawner, and IPC execution helpers.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

pub mod cli;

pub use cli::{
    BackupAddArgs, BackupCommands, Cli, Commands, ENV_EC_PASSPHRASE, ENV_ZV_PASSPHRASE,
    NoteCommands, OAuthKindArg, RemoteAddArgs, RemoteCommands, RemoteKindArg, RemoteOAuthArgs,
    RoutingPolicyArg, SetPolicyArgs, ShareCommands, build_daemon_request, locate_sibling_daemon_exe,
    parse_cli_from, read_secret_line, resolve_passphrase, run_cli_with_io,
    run_local_crypto_benchmark,
};

#[cfg(test)]
mod unit_tests {
    use std::io::Cursor;

    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_command_schema_and_zeroizing_secret_reader_work() -> anyhow::Result<()> {
        Cli::command().debug_assert();
        if Cli::command().get_name() != "ec" {
            anyhow::bail!("expected CLI binary name 'ec'");
        }

        let mut stdin = Cursor::new(b"  \n".to_vec());
        let mut stderr = Vec::new();
        if read_secret_line(&mut stdin, None, &mut stderr).is_ok() {
            let mut empty_in = Cursor::new(b"\n".to_vec());
            if read_secret_line(&mut empty_in, None, &mut stderr).is_ok() {
                anyhow::bail!("expected empty newline passphrase rejection");
            }
        }

        let mut eof_in = Cursor::new(Vec::<u8>::new());
        if read_secret_line(&mut eof_in, None, &mut stderr).is_ok() {
            anyhow::bail!("expected EOF passphrase rejection");
        }

        let mut valid_in = Cursor::new(b"zeroized-passphrase-value\r\n".to_vec());
        let secret = resolve_passphrase(true, &mut valid_in, &mut stderr)?;
        if secret.as_str() != "zeroized-passphrase-value" {
            anyhow::bail!("unexpected resolved passphrase");
        }
        Ok(())
    }
}
