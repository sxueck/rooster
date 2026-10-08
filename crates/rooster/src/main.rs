//! `rooster` 单二进制入口:agent 与 hub 共用一个可执行文件。

use clap::{Parser, Subcommand};
use rooster_config::UpgradeMethod;
use std::path::PathBuf;
use std::process::ExitCode;

/// `--upgrade-method` 值解析:与 config 的 `local.upgrade.method` 同词汇,
/// 但只作为运行时覆盖,不回写 enrolled 配置。
fn parse_upgrade_method(s: &str) -> Result<UpgradeMethod, String> {
    match s {
        "systemd" => Ok(UpgradeMethod::Systemd),
        "exit" => Ok(UpgradeMethod::Exit),
        "none" => Ok(UpgradeMethod::None),
        _ => Err(format!("expected one of `systemd`, `exit`, `none`, got `{s}`")),
    }
}

#[derive(Parser)]
#[command(name = "rooster", version = rooster_agent::hubclient::reported_version(), about = "port protection agent and management hub")]
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
        /// Runtime override of local.agent.data-dir (container: /var/lib/rooster).
        /// Applied on top of every effective-config read; never written back.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Runtime override of local.upgrade.method (container: `exit`).
        #[arg(long, value_parser = parse_upgrade_method)]
        upgrade_method: Option<UpgradeMethod>,
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
    /// 启动前钩子:升级失败时回退 Agent 二进制。容器模式下由不可变
    /// 守护进程调用,须显式指定可变 Agent 二进制。
    UpgradeGuard {
        #[arg(long, default_value = "/var/lib/rooster")]
        data_dir: PathBuf,
        /// Explicit agent executable to restore (container:
        /// /var/lib/rooster/bin/rooster). Rollback source is `<binary>.prev`.
        #[arg(long)]
        binary: Option<PathBuf>,
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
        Command::Agent {
            config,
            data_dir,
            upgrade_method,
            cmd: None,
        } => {
            rooster_agent::run(
                &config,
                rooster_agent::state::RuntimeOverrides {
                    data_dir,
                    upgrade_method,
                },
            )
            .await
        }
        Command::Agent {
            cmd: Some(AgentCmd::UpgradeGuard { data_dir, binary }),
            ..
        } => {
            let code = rooster_agent::upgrade::guard(&data_dir, binary.as_deref());
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

#[cfg(test)]
mod tests {
    #[test]
    fn cli_version_matches_agent_hello() {
        use clap::CommandFactory;

        let command = super::Cli::command();
        assert_eq!(command.get_version(), Some(rooster_agent::hubclient::reported_version()));
    }
}
