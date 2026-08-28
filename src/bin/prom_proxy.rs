//! Prometheus remote_write TCP 代理进程。

use std::env;
use std::net::SocketAddr;
use std::process;

use proto4::prom_proxy::{Server, ServerConfig};
use proto4::tiny_frame::{self, KEY_LEN};

fn usage() -> ! {
    eprintln!(
        "Usage: prom_proxy [--listen <addr>] [--prometheus-url <url>] \
         [--redis-url <url>] [--secretkey <64-hex>]\n\n\
         Or set env: PROM_PROXY_LISTEN, PROM_PROXY_URL, PROM_PROXY_REDIS_URL, \
         PROM_PROXY_SECRETKEY\n\n\
         Example:\n  prom_proxy --listen 0.0.0.0:9100 \\\n\
         --prometheus-url http://127.0.0.1:9090/api/v1/write \\\n\
         --redis-url redis://127.0.0.1:6379 \\\n\
         --secretkey 071c9849f90b8caf7b9083bd53817e56d7274dc35796c4206b7fc97caec44dea"
    );
    process::exit(2);
}

fn parse_args() -> (SocketAddr, String, String, [u8; KEY_LEN]) {
    let mut listen: Option<String> = None;
    let mut prometheus_url: Option<String> = None;
    let mut redis_url: Option<String> = None;
    let mut secretkey: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = Some(args.next().unwrap_or_else(|| usage())),
            "--prometheus-url" => prometheus_url = Some(args.next().unwrap_or_else(|| usage())),
            "--redis-url" => redis_url = Some(args.next().unwrap_or_else(|| usage())),
            "--secretkey" => secretkey = Some(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }

    let listen_s = listen
        .or_else(|| env::var("PROM_PROXY_LISTEN").ok())
        .unwrap_or_else(|| usage());
    let prometheus_url = prometheus_url
        .or_else(|| env::var("PROM_PROXY_URL").ok())
        .unwrap_or_else(|| usage());
    let redis_url = redis_url
        .or_else(|| env::var("PROM_PROXY_REDIS_URL").ok())
        .unwrap_or_else(|| usage());
    let key_hex = secretkey
        .or_else(|| env::var("PROM_PROXY_SECRETKEY").ok())
        .unwrap_or_else(|| usage());

    let listen: SocketAddr = listen_s.parse().unwrap_or_else(|e| {
        eprintln!("invalid listen addr {listen_s:?}: {e}");
        process::exit(1);
    });
    let raw = hex_decode(&key_hex).unwrap_or_else(|e| {
        eprintln!("invalid secretkey: {e}");
        process::exit(1);
    });
    if raw.len() != KEY_LEN {
        eprintln!(
            "secretkey must be {KEY_LEN} bytes ({} hex chars), got {}",
            KEY_LEN * 2,
            raw.len()
        );
        process::exit(1);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw);
    (listen, prometheus_url, redis_url, key)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[tokio::main]
async fn main() {
    let (listen, prometheus_url, redis_url, key) = parse_args();
    tiny_frame::set_encrypt_key(Some(key));

    let server = match Server::new(ServerConfig::new(listen, prometheus_url.clone(), redis_url.clone())).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("prom_proxy: init failed: {e}");
            process::exit(1);
        }
    };
    eprintln!(
        "prom_proxy listening on {listen}, forwarding to {prometheus_url}, redis {redis_url}"
    );
    match server.spawn().await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("prom_proxy exited: {e}");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("prom_proxy task join error: {e}");
            process::exit(1);
        }
    }
}
