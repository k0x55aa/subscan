use std::fs::File;
use std::io::{BufRead, BufReader, Write, stdout};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use hickory_client::client::ClientHandle;
use tokio::sync::{mpsc, Semaphore};
use tokio::task;
use hickory_client::client::Client;
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;


#[derive(Serialize, Clone)]
pub struct SubdomainScanner {
    resolvers: Vec<SocketAddr>,
    domain: String,
    subdomains: Vec<String>,
    timeout: Duration,
    concurrency_limit: u32,
}

impl SubdomainScanner {
    pub async fn new(
        resolvers_file: &str,
        subdomains_file: &str,
        domain: &str,
        timeout_secs: u64,
        concurrency_limit: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let resolvers = read_lines(resolvers_file)?
            .filter_map(|line| line.ok())
            .filter_map(|line| {
                if line.contains(':') {
                    SocketAddr::from_str(&line).ok()
                } else {
                    SocketAddr::from_str(&format!("{}:53", line.trim())).ok()
                }
            })
            .collect::<Vec<_>>();

        let subdomains = read_lines(subdomains_file)?
            .filter_map(|line| line.ok())
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();

        if resolvers.is_empty() {
            return Err("No valid resolvers found".into());
        }

        Ok(Self {
            resolvers,
            domain: domain.to_string(),
            subdomains,
            timeout: Duration::from_secs(timeout_secs),
            concurrency_limit,
        })
    }

    async fn try_resolve_once(resolver: SocketAddr, timeout: Duration, full_domain: String) -> Option<String> {
        let name = Name::from_str(&format!("{}.", full_domain)).ok()?;
        let conn = UdpClientStream::builder(resolver, TokioRuntimeProvider::default())
            .with_timeout(Some(timeout))
            .build();
        let (mut client, bg) = Client::connect(conn).await.ok()?;
        tokio::spawn(bg);
        let resp = client.query(name, DNSClass::IN, RecordType::A).await.ok()?;
        if !resp.answers().is_empty() {
            Some(full_domain)
        } else {
            None
        }
    }

    pub async fn scan(&self) -> Value {
        let (tx, mut rx) = mpsc::channel(self.concurrency_limit as usize);
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit as usize));

        for (i, subdomain) in self.subdomains.clone().into_iter().enumerate() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let tx = tx.clone();
            let resolver = self.resolvers[i % self.resolvers.len()];
            let domain = self.domain.clone();
            let timeout = self.timeout;

            task::spawn(async move {
                let _permit = permit;
                let full_domain = format!("{}.{}", subdomain, domain);
                if let Some(found) = SubdomainScanner::try_resolve_once(resolver, timeout, full_domain).await {
                    let _ = tx.send(found).await;
                }
            });
        }

        drop(tx);

        let mut found_domains = Vec::new();

        while let Some(found) = rx.recv().await {
            print!("{}\n", found);
            stdout().flush().unwrap();
            found_domains.push(found);
        }

        json!({
            "target": self.domain,
            "results": {
                "subdomain": found_domains,
                "total_scanned": self.subdomains.len(),
                "resolvers_used": self.resolvers.len()
            }
        })
    }
}

fn read_lines(path: &str) -> std::io::Result<impl Iterator<Item = std::io::Result<String>>> {
    let file = File::open(path)?;
    Ok(BufReader::new(file).lines())
}
