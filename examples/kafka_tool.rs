//! Kafka harness helper (tests/e2e/kafka_out.sh): reads back what a collector produced in PCE Kafka
//! mode, or feeds lines into a topic.
//!
//! ```text
//! kafka_tool dump --brokers B --topic T --out DIR [--sasl-password-file F] [--insecure]
//! kafka_tool produce --brokers B --topic T [--sasl-password-file F] [--insecure]
//! ```
//!
//! `dump` reads every partition of T from its earliest offset and writes each record's value to
//! `DIR/<partition>-<offset>.pb.gz` and its key (empty when there is none) as one line of
//! `DIR/keys.txt`, until no new record has come for 10 s. `produce` sends each stdin line as one
//! record (no key) to partition 0.
//!
//! With `--sasl-password-file` the connection is TLS with SASL PLAIN, user `$ConnectionString`
//! and the file's content (one trailing newline dropped) as password, as for an Event Hubs
//! connection string; the password is never taken from argv. `--insecure` skips the broker
//! certificate check. Without a password file the connection is PLAINTEXT.
//!
//! Not shipped: this is an example, built only for the harness.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use flowpilot::kafka::producer::{split_brokers, SASL_USER};
use flowpilot::kafka::{runtime, tls};
use rskafka::client::partition::{Compression, OffsetAt, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder, Credentials, SaslConfig};
use rskafka::record::Record;

/// `dump` stops once no record has arrived for this long.
const IDLE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Args {
    cmd: String,
    brokers: String,
    topic: String,
    out: Option<PathBuf>,
    password_file: Option<PathBuf>,
    insecure: bool,
}

fn parse() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;
    let mut a = Args::default();
    let mut p = lexopt::Parser::from_env();
    while let Some(arg) = p.next()? {
        match arg {
            Value(v) if a.cmd.is_empty() => a.cmd = v.string()?,
            Long("brokers") => a.brokers = p.value()?.string()?,
            Long("topic") => a.topic = p.value()?.string()?,
            Long("out") => a.out = Some(p.value()?.into()),
            Long("sasl-password-file") => a.password_file = Some(p.value()?.into()),
            Long("insecure") => a.insecure = true,
            _ => return Err(arg.unexpected()),
        }
    }
    Ok(a)
}

async fn connect(a: &Args) -> Result<Client, String> {
    let mut b = ClientBuilder::new(split_brokers(&a.brokers));
    if let Some(f) = &a.password_file {
        let pw = fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let pw = pw.strip_suffix('\n').unwrap_or(&pw).to_string();
        b = b
            .tls_config(tls::server_config(!a.insecure))
            .sasl_config(SaslConfig::Plain(Credentials::new(SASL_USER.to_string(), pw)));
    }
    tokio::time::timeout(Duration::from_secs(30), b.build())
        .await
        .map_err(|_| "no connection to Kafka within 30s".to_string())?
        .map_err(|e| e.to_string())
}

async fn dump(a: &Args) -> Result<(), String> {
    let out = a.out.clone().ok_or("dump needs --out")?;
    fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let client = connect(a).await?;
    let topics = client.list_topics().await.map_err(|e| e.to_string())?;
    let partitions = topics
        .into_iter()
        .find(|t| t.name == a.topic)
        .ok_or_else(|| format!("topic {} not found", a.topic))?
        .partitions;
    let mut next = BTreeMap::new();
    for p in partitions {
        let pc = client
            .partition_client(a.topic.clone(), p, UnknownTopicHandling::Error)
            .await
            .map_err(|e| e.to_string())?;
        let start = pc.get_offset(OffsetAt::Earliest).await.map_err(|e| e.to_string())?;
        next.insert(p, (pc, start));
    }
    let mut keys = fs::File::create(out.join("keys.txt")).map_err(|e| e.to_string())?;
    let (mut count, mut last) = (0usize, Instant::now());
    while last.elapsed() < IDLE {
        for (p, (pc, offset)) in next.iter_mut() {
            let (records, _) = pc.fetch_records(*offset, 1..10_000_000, 500).await.map_err(|e| e.to_string())?;
            for r in records {
                fs::write(out.join(format!("{p}-{}.pb.gz", r.offset)), r.record.value.unwrap_or_default())
                    .map_err(|e| e.to_string())?;
                let key = r.record.key.unwrap_or_default();
                writeln!(keys, "{}", String::from_utf8_lossy(&key)).map_err(|e| e.to_string())?;
                *offset = r.offset + 1;
                count += 1;
                last = Instant::now();
            }
        }
    }
    println!("dumped {count} records from topic {}", a.topic);
    Ok(())
}

async fn produce(a: &Args) -> Result<(), String> {
    let client = connect(a).await?;
    let pc = client
        .partition_client(a.topic.clone(), 0, UnknownTopicHandling::Error)
        .await
        .map_err(|e| e.to_string())?;
    let mut count = 0usize;
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let record = Record {
            key: None,
            value: Some(line.into_bytes()),
            headers: BTreeMap::new(),
            timestamp: chrono::Utc::now(),
        };
        pc.produce(vec![record], Compression::NoCompression).await.map_err(|e| e.to_string())?;
        count += 1;
    }
    println!("produced {count} records to topic {}", a.topic);
    Ok(())
}

fn main() -> ExitCode {
    let a = match parse() {
        Ok(a) if !a.brokers.is_empty() && !a.topic.is_empty() => a,
        Ok(_) => {
            eprintln!("kafka_tool: --brokers and --topic are required");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("kafka_tool: {e}");
            return ExitCode::from(2);
        }
    };
    let r = match a.cmd.as_str() {
        "dump" => runtime().block_on(dump(&a)),
        "produce" => runtime().block_on(produce(&a)),
        c => Err(format!("unknown command {c:?}; use dump or produce")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kafka_tool: {e}");
            ExitCode::FAILURE
        }
    }
}
