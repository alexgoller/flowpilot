//! The installer subcommands. Each `run_*` returns the process exit code.

pub mod answers;
pub mod apply;
pub mod args;
pub mod check;
pub mod health;
pub mod render;
pub mod run;
pub mod status;
pub mod system;
pub mod uninstall;
pub mod wizard;

use args::{InstallArgs, StatusArgs, UninstallArgs};

pub fn run_install(args: InstallArgs) -> i32 {
    run::run_install(args)
}

pub fn run_uninstall(args: UninstallArgs) -> i32 {
    uninstall::run_uninstall(args)
}

pub fn run_rollback() -> i32 {
    uninstall::run_rollback()
}

pub fn run_status(args: StatusArgs) -> i32 {
    status::run_status(args)
}
