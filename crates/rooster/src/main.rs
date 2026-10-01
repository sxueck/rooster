//! `rooster` 单二进制入口:agent 与 hub 共用一个可执行文件。

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "rooster", version, about = "port protection agent and management hub")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the protection agent on a node.
    Agent {
        /// Path to config.yaml.
        #[arg(long, default_value = "/etc/rooster/config.yaml")]
        config: PathBuf,
        #[command(subcommand)]
        cmd: Option<AgentCmd>,
    },
    /// Run the management hub.
    Hub {
        /// Path to hub.yaml.
        #[arg(long, default_value = "/etc/rooster/hub.yaml")]
        config: PathBuf,
        #[command(subcommand)]
        cmd: Option<HubCmd>,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// systemd ExecStartPre 钩子:升级失败时回退 rooster.prev。
    UpgradeGuard {
        #[arg(long, default_value = "/var/lib/rooster")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum HubCmd {
    /// 导出 redb 与 PKI 到目录。
    Backup { out: PathBuf },
    /// 从备份目录恢复。
    Restore { from: PathBuf },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Agent { config, cmd: None } => rooster_agent::run(&config).await,
        Command::Agent {
            config: _,
            cmd: Some(AgentCmd::UpgradeGuard { data_dir }),
        } => {
            let code = rooster_agent::upgrade::guard(&data_dir);
            ExitCode::from(code as u8)
        }
        Command::Hub { config, cmd: None } => match rooster_hub::run(&config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rooster hub: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Hub { config, cmd: Some(HubCmd::Backup { out }) } => {
            match rooster_hub::backup(&config, &out) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("rooster hub backup: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Hub { config, cmd: Some(HubCmd::Restore { from }) } => {
            match rooster_hub::restore(&config, &from) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("rooster hub restore: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
