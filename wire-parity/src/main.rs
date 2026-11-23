//! Live wire-parity runner: performs a real TLS handshake with the
//! requested identity against a real server and asserts the fingerprint
//! the server sees. Mirrors the lyrebird probe's native live path: the
//! same provider discipline (config and verifier share one provider)
//! and the same shaped ClientHello the browsers send.

use std::{io::Read, io::Write, net::TcpStream, sync::Arc};

use epoxy_hello::HelloIdentity;
use rustls::{pki_types::ServerName, RootCertStore, Stream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgIdentity {
	Native,
	Brave,
	Firefox,
}

impl ArgIdentity {
	fn parse(s: &str) -> Option<Self> {
		match s {
			"native" => Some(Self::Native),
			"brave" => Some(Self::Brave),
			"firefox" => Some(Self::Firefox),
			_ => None,
		}
	}

	fn hello(self) -> HelloIdentity {
		match self {
			Self::Native => HelloIdentity::Native,
			Self::Brave => HelloIdentity::Brave,
			Self::Firefox => HelloIdentity::Firefox,
		}
	}
}

fn build_config(identity: HelloIdentity) -> rustls::ClientConfig {
	let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
	// builder_with_provider keeps the built-in webpki verifier on the
	// SAME provider, so supported_verify_schemes() (which builds the
	// ClientHello signature_algorithms) advertises the right list.
	let builder = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
		.expect("protocol versions");
	let mut roots = RootCertStore::empty();
	roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	let config = builder
		.with_root_certificates(roots)
		.with_no_client_auth();

	let mut config = match epoxy_hello::profile(identity) {
		Some(p) => config.with_client_hello_profile(p),
		None => config,
	};
	let alpn = epoxy_hello::alpn(identity);
	if !alpn.is_empty() {
		config.alpn_protocols = alpn;
		config.cert_decompressors = epoxy_hello::cert_decompressors(identity);
	}
	config
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	if args.len() < 5 {
		eprintln!(
			"usage: wire-parity <brave|firefox|native> <host> <port> <path> [--expect-ja4 <part>]"
		);
		std::process::exit(2);
	}
	let identity = match ArgIdentity::parse(&args[1]) {
		Some(i) => i,
		None => {
			eprintln!("unknown identity {}", args[1]);
			std::process::exit(2);
		}
	};
	let host = args[2].clone();
	let port: u16 = args[3].parse().expect("port");
	let path = args[4].clone();
	let expect_ja4 = args
		.iter()
		.position(|a| a == "--expect-ja4")
		.map(|i| args[i + 1].clone());

	let config = build_config(identity.hello());
	let name = ServerName::try_from(host.clone()).expect("server name");
	let mut conn =
		rustls::ClientConnection::new(Arc::new(config), name).expect("client connection");
	let mut sock = TcpStream::connect((host.as_str(), port)).expect("tcp connect");
	let mut tls = Stream::new(&mut conn, &mut sock);

	let req = format!(
		"GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wire-parity/0.1\r\nConnection: close\r\n\r\n",
		path, host
	);
	tls.write_all(req.as_bytes()).expect("write request");
	tls.flush().expect("flush");
	let mut buf = Vec::new();
	let _ = tls.read_to_end(&mut buf);
	let body = String::from_utf8_lossy(&buf);
	print!("{body}");

	if let Some(expected) = expect_ja4 {
		if !body.contains(&expected) {
			eprintln!("FINGERPRINT MISMATCH: expected ja4 part {expected:?} absent");
			std::process::exit(1);
		}
		eprintln!("ja4 parity ok: {expected}");
	}
}
