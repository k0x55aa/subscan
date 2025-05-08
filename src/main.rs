use subscan::scanner::SubdomainScanner;
use std::fs::File;
use clap::Parser;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "Subbrute", version="0.1", about = "It checks for package in npm public repo")]
struct ArgumentCli {
    /// list of dns resolvers
    #[arg(short, long, default_value = "")]
    resolvers: String,
    /// wordlist containing subdomains
    #[arg(short, long, default_value = "")]
    wordlist: String,
    /// domain name
    #[arg(short, long, default_value = "")]
    domain: String,
    /// output json
    #[arg(short, long, default_value = "")]
    output: String,
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ArgumentCli::parse();

    let scanner = SubdomainScanner::new(
        &args.resolvers,
       &args.wordlist,
        &args.domain,
        2,
    ).await?;

    let results = scanner.scan().await;
    let json = serde_json::to_string_pretty(&results)?;

    if args.output != "" {
        let mut file = File::create(&args.output)?;
        file.write_all(json.as_bytes())?;
    }
    Ok(())
}