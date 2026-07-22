//! CLI module for Graphite Core.

use crate::verification::{GraphiteCore, VerificationInput};
use std::path::PathBuf;

pub enum CliCommand {
    Verify { input: VerificationInput },
    Server { port: u16 },
    Manifests,
    Benchmark,
}

pub fn run(command: CliCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CliCommand::Verify { input } => {
            let core = GraphiteCore::new();
            let result = core.verify(&input)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        CliCommand::Manifests => {
            let core = GraphiteCore::new();
            for m in core.list_manifests() {
                println!("  {} ({}) — {} instructions",
                    m.protocol.name,
                    m.protocol.program_id,
                    m.instructions.len()
                );
            }
            Ok(())
        }
        CliCommand::Benchmark => {
            crate::benchmark::run_benchmark();
            Ok(())
        }
        CliCommand::Server { port } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(crate::server::run_server(([0, 0, 0, 0], port).into()))?;
            Ok(())
        }
    }
}

pub fn verify_from_file(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let input: VerificationInput = serde_json::from_str(&content)?;
    run(CliCommand::Verify { input })
}

pub fn verify_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut content = String::new();
    std::io::stdin().read_to_string(&mut content)?;
    let input: VerificationInput = serde_json::from_str(&content)?;
    run(CliCommand::Verify { input })
}
