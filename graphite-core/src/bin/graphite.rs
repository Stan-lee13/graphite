use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "graphite", about = "Graphite — Transaction verification for Solana AI agents", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a transaction from a JSON file
    Verify {
        /// Path to JSON verification input
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Read JSON from stdin instead of file
        #[arg(long)]
        stdin: bool,
    },
    /// List loaded protocol manifests
    Manifests,
    /// Start the HTTP verification server
    #[cfg(feature = "server")]
    Server {
        /// Port to listen on (default: 7331)
        #[arg(short, long, default_value = "7331")]
        port: u16,
    },
    /// Run the benchmark suite
    Benchmark,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { file: Some(path), stdin: false } => {
            graphite_core::cli::verify_from_file(&path)
        }
        Commands::Verify { file: None, stdin: true } => {
            graphite_core::cli::verify_from_stdin()
        }
        Commands::Verify { .. } => {
            eprintln!("Error: specify --file <path> or --stdin");
            std::process::exit(1);
        }
        Commands::Manifests => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Manifests)
        }
        #[cfg(feature = "server")]
        Commands::Server { port } => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Server { port })
        }
        Commands::Benchmark => {
            graphite_core::cli::run(graphite_core::cli::CliCommand::Benchmark)
        }
    }
}
