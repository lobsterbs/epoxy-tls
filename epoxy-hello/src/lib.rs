//! TLS-identity shaping for the epoxy stack.
//!
//! Maps a caller [`HelloIdentity`] to the frozen browser ClientHello
//! profiles that live inside the lyrebird-patched vendored rustls
//! (`rustls::client::browser_profiles`). All wire data is owned by that
//! single patched copy: this crate only maps identities, it carries no
//! profile bytes of its own.

use rustls::client::{browser_profiles, ClientHelloProfile};

/// The client identity an embedding engine claims on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloIdentity {
	/// Stock rustls ClientHello: shaping off, no cert compression.
	Native,
	/// Brave (Chromium 158) wire shape, GREASE bookends, GREASE ECH.
	Brave,
	/// Firefox 160 wire shape, no GREASE, GREASE ECH.
	Firefox,
}

/// The frozen ClientHello profile for `identity`.
///
/// `None` for [`HelloIdentity::Native`] (stock handshake).
pub fn profile(identity: HelloIdentity) -> Option<&'static ClientHelloProfile> {
	match identity {
		HelloIdentity::Native => None,
		HelloIdentity::Brave => Some(browser_profiles::brave()),
		HelloIdentity::Firefox => Some(browser_profiles::firefox()),
	}
}

/// The cert-decompression algorithms `identity` advertises, in its wire
/// order. Empty for [`HelloIdentity::Native`].
pub fn cert_decompressors(
	identity: HelloIdentity,
) -> Vec<&'static dyn rustls::compress::CertDecompressor> {
	match identity {
		HelloIdentity::Native => Vec::new(),
		HelloIdentity::Brave => {
			browser_profiles::cert_decompressors(browser_profiles::BRAVE_COMPRESSION)
		}
		HelloIdentity::Firefox => {
			browser_profiles::cert_decompressors(browser_profiles::FIREFOX_COMPRESSION)
		}
	}
}

/// ALPN protocols `identity` offers, in wire order. Empty for
/// [`HelloIdentity::Native`] so callers keep their own choice.
pub fn alpn(identity: HelloIdentity) -> Vec<Vec<u8>> {
	match identity {
		HelloIdentity::Native => Vec::new(),
		_ => browser_profiles::alpn(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn native_is_unshaped() {
		assert!(profile(HelloIdentity::Native).is_none());
		assert!(cert_decompressors(HelloIdentity::Native).is_empty());
		assert!(alpn(HelloIdentity::Native).is_empty());
	}

	#[test]
	fn brave_profile_is_the_captured_shape() {
		let p = profile(HelloIdentity::Brave).expect("brave profile");
		assert!(p.grease, "brave sends GREASE bookends");
		assert_eq!(p.cipher_suites.len(), 15, "captured cipher list");
		assert_eq!(p.signature_schemes.len(), 11, "captured sig list");
	}

	#[test]
	fn firefox_profile_is_the_captured_shape() {
		let p = profile(HelloIdentity::Firefox).expect("firefox profile");
		assert!(!p.grease, "firefox sends no GREASE");
		assert_eq!(p.signature_schemes.len(), 11, "captured sig list");
	}

	#[test]
	fn cert_compression_lists_match_profiles() {
		assert_eq!(
			cert_decompressors(HelloIdentity::Brave).len(),
			1,
			"brave: brotli only"
		);
		assert_eq!(
			cert_decompressors(HelloIdentity::Firefox).len(),
			2,
			"firefox: zlib + brotli"
		);
	}

	#[test]
	fn alpn_lists_browser_order() {
		assert_eq!(
			alpn(HelloIdentity::Brave),
			vec![b"h2".to_vec(), b"http/1.1".to_vec()]
		);
	}
}
