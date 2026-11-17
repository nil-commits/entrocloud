//! Zerovault CLI library surface exposing testable parser and execution helpers.

pub mod cli;

pub use cli::{
    Cli, Commands, RemoteAddArgs, RemoteCommands, RemoteKindArg, RoutingPolicyArg,
    build_daemon_request, parse_cli_from, read_secret_line, run_cli_with_io,
    run_local_crypto_benchmark,
};
