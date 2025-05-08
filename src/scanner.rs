use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use tokio::sync::{mpsc, Semaphore};
use tokio::task;

use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use tokio::sync::watch;


#[derive(Serialize)]
pub struct SubdomainScanner {
    resolvers: Vec<SocketAddr>,
    domain: String,
    subdomains: Vec<String>,
    timeout: Duration,
}

impl SubdomainScanner {
    pub async fn new(
        resolvers_file: &str,
        subdomains_file: &str,
        domain: &str,
        timeout_secs: u64,
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
        })
    }


    async fn try_resolvers(
        resolvers: Vec<SocketAddr>,
        timeout: Duration,
        full_domain: String,
    ) -> Option<String> {
        let name = Name::from_str(&format!("{}.", full_domain)).ok()?;
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mut handles = Vec::new();
    
        for resolver in resolvers {
            let name = name.clone();
            let full_domain = full_domain.clone();
            let mut cancel_rx = cancel_rx.clone();
    
            let handle = tokio::spawn(async move {
                tokio::select! {
                    _ = cancel_rx.changed() => None,
                    result = async {
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
                    } => result
                }
            });
    
            handles.push(handle);
        }
    
        for handle in handles {
            if let Ok(Some(found)) = handle.await {
                let _ = cancel_tx.send(true);
                return Some(found);
            }
        }
    
        None
    }
    

    pub async fn scan(&self) -> Value {
        let (tx, mut rx) = mpsc::channel(1000000);
        let semaphore = Arc::new(Semaphore::new(1000000));

        for subdomain in self.subdomains.clone() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let tx = tx.clone();
            let resolvers = self.resolvers.clone();
            let domain = self.domain.clone();
            let timeout = self.timeout;

            task::spawn(async move {
                let _permit = permit;
                let full_domain = format!("{}.{}", subdomain, domain);
                if let Some(found) = SubdomainScanner::try_resolvers(resolvers, timeout, full_domain).await {
                    let _ = tx.send(found).await;
                }
            });
        }

        drop(tx);

        let mut found_domains = Vec::new();
        while let Some(found) = rx.recv().await {
            println!("{}", found);
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

impl Clone for SubdomainScanner {
    fn clone(&self) -> Self {
        Self {
            resolvers: self.resolvers.clone(),
            domain: self.domain.clone(),
            subdomains: self.subdomains.clone(),
            timeout: self.timeout,
        }
    }
}

fn read_lines(path: &str) -> std::io::Result<impl Iterator<Item = std::io::Result<String>>> {
    let file = File::open(path)?;
    Ok(BufReader::new(file).lines())
}
