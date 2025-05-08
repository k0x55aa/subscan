use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;
use log::{info, warn};
use rand::seq::SliceRandom;
use tracing::debug;


use crate::dns::DnsRecordType;

#[derive(Parser, Debug)]
#[command(name = "massdns-rs")]
#[command(version, about = "High-performance DNS resolver", long_about = None)]
pub struct Cli {
    /// File containing DNS resolvers (one per line)
    #[arg(short, long, value_name = "FILE")]
    pub resolvers: PathBuf,

    /// File containing domains to resolve (one per line)
    #[arg(short, long, value_name = "FILE")]
    pub domains: PathBuf,

    /// Output file (stdout if not specified)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// DNS record type to query (A, AAAA, MX, etc.)
    #[arg(short, long, default_value = "A", value_name = "TYPE")]
    pub record_type: String,

    /// Comma-separated list of record types to query
    #[arg(long, value_name = "TYPES", conflicts_with = "record_type")]
    pub record_types: Option<String>,

    /// Limit queries per second
    #[arg(short, long, value_name = "N")]
    pub rate_limit: Option<u32>,

    /// Query timeout in seconds
    #[arg(long, default_value = "2", value_name = "SECS")]
    pub timeout: u64,

    /// Enable TCP fallback for large responses
    #[arg(long)]
    pub tcp: bool,

    /// Use TCP only (no UDP)
    #[arg(long)]
    pub tcp_only: bool,

    /// Number of sockets to use
    #[arg(long, default_value_t = num_cpus::get(), value_name = "N")]
    pub sockets: usize,

    /// Output format
    #[arg(long, default_value = "text", value_name = "FORMAT")]
    pub output_format: OutputFormat,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Randomize the order of domains
    #[arg(long)]
    pub shuffle: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

impl Cli {
    pub fn to_config(&self) -> anyhow::Result<crate::MassDnsConfig> {
        let record_types = self.parse_record_types()?;
        let resolvers = self.load_resolvers()?;
        let mut domains = self.load_domains()?;

        if self.shuffle {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            domains.shuffle(&mut rng);
            info!("Shuffled {} domains", domains.len());
        }

        Ok(crate::MassDnsConfig {
            resolvers,
            domains,
            output_file: self.output.clone(),
            record_types,
            rate_limit: self.rate_limit.map(|r| r as usize),
            timeout: Duration::from_secs(self.timeout),
            tcp_enabled: self.tcp || self.tcp_only,
            tcp_only: self.tcp_only,
            socket_count: self.sockets,
            output_format: self.output_format,
        })
    }

    fn parse_record_types(&self) -> anyhow::Result<Vec<DnsRecordType>> {
        if let Some(types) = &self.record_types {
            let record_types: anyhow::Result<Vec<_>> = types
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    DnsRecordType::from_str(s)
                        .map_err(|e| anyhow::anyhow!("Invalid record type '{}': {}", s, e))
                })
                .collect();
            
            let record_types = record_types?;
            debug!("Parsed record types: {:?}", record_types);
            Ok(record_types)
        } else {
            let record_type = DnsRecordType::from_str(&self.record_type).unwrap_or_else(|_| {
                warn!("Invalid record type '{}', defaulting to A", self.record_type);
                DnsRecordType::A
            });
            debug!("Using single record type: {:?}", record_type);
            Ok(vec![record_type])
        }
    }

    fn load_resolvers(&self) -> anyhow::Result<Vec<SocketAddr>> {
        let file = File::open(&self.resolvers)?;
        let reader = BufReader::new(file);
        let mut resolvers = Vec::new();
        let mut invalid_count = 0;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let addr = if line.contains(':') {
                line.to_string()
            } else {
                format!("{}:53", line)
            };

            match addr.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        resolvers.push(addr);
                    }
                }
                Err(e) => {
                    invalid_count += 1;
                    warn!(
                        "Invalid resolver at {}:{} - '{}' ({})",
                        self.resolvers.display(),
                        line_num + 1,
                        line,
                        e
                    );
                }
            }
        }

        if resolvers.is_empty() {
            anyhow::bail!(
                "No valid DNS resolvers found in {} ({} invalid entries)",
                self.resolvers.display(),
                invalid_count
            );
        }

        info!(
            "Loaded {} DNS resolvers from {} ({} invalid entries skipped)",
            resolvers.len(),
            self.resolvers.display(),
            invalid_count
        );
        Ok(resolvers)
    }

    fn load_domains(&self) -> anyhow::Result<Vec<String>> {
        let file = File::open(&self.domains)?;
        let reader = BufReader::new(file);
        let mut domains = Vec::new();
        let mut invalid_count = 0;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if is_valid_domain(line) {
                domains.push(line.to_lowercase());
            } else {
                invalid_count += 1;
                warn!(
                    "Invalid domain at {}:{} - '{}'",
                    self.domains.display(),
                    line_num + 1,
                    line
                );
            }
        }

        if domains.is_empty() {
            anyhow::bail!(
                "No valid domains found in {} ({} invalid entries)",
                self.domains.display(),
                invalid_count
            );
        }

        info!(
            "Loaded {} domains from {} ({} invalid entries skipped)",
            domains.len(),
            self.domains.display(),
            invalid_count
        );
        Ok(domains)
    }
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    let mut label_chars = 0;
    for c in domain.chars() {
        if c == '.' {
            if label_chars == 0 || label_chars > 63 {
                return false;
            }
            label_chars = 0;
        } else {
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return false;
            }
            label_chars += 1;
            if label_chars > 63 {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_resolvers() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "1.1.1.1").unwrap();
        writeln!(file, "8.8.8.8:53").unwrap();
        writeln!(file, "# Comment").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "invalid.resolver").unwrap();

        let cli = Cli {
            resolvers: file.path().to_path_buf(),
            domains: PathBuf::from(""),
            output: None,
            record_type: "A".to_string(),
            record_types: None,
            rate_limit: None,
            timeout: 2,
            tcp: false,
            tcp_only: false,
            sockets: 4,
            output_format: OutputFormat::Text,
            verbose: false,
            shuffle: false,
        };

        let resolvers = cli.load_resolvers().unwrap();
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].port(), 53);
        assert_eq!(resolvers[1].port(), 53);
    }

    #[test]
    fn test_load_domains() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "example.com").unwrap();
        writeln!(file, "sub.example.com").unwrap();
        writeln!(file, "# Comment").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "invalid..domain").unwrap();

        let cli = Cli {
            resolvers: PathBuf::from(""),
            domains: file.path().to_path_buf(),
            output: None,
            record_type: "A".to_string(),
            record_types: None,
            rate_limit: None,
            timeout: 2,
            tcp: false,
            tcp_only: false,
            sockets: 4,
            output_format: OutputFormat::Text,
            verbose: false,
            shuffle: false,
        };

        let domains = cli.load_domains().unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0], "example.com");
        assert_eq!(domains[1], "sub.example.com");
    }

    #[test]
    fn test_parse_record_types() {
        let cli = Cli {
            resolvers: PathBuf::from(""),
            domains: PathBuf::from(""),
            output: None,
            record_type: "AAAA".to_string(),
            record_types: None,
            rate_limit: None,
            timeout: 2,
            tcp: false,
            tcp_only: false,
            sockets: 4,
            output_format: OutputFormat::Text,
            verbose: false,
            shuffle: false,
        };

        assert_eq!(cli.parse_record_types().unwrap(), vec![DnsRecordType::AAAA]);

        let cli = Cli {
            record_types: Some("A,AAAA,MX".to_string()),
            ..cli
        };

        assert_eq!(
            cli.parse_record_types().unwrap(),
            vec![DnsRecordType::A, DnsRecordType::AAAA, DnsRecordType::MX]
        );
    }
}