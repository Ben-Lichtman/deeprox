use std::fs::File;
use std::io::{Cursor, Read, Write};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder, X509Ref, X509};

use rustls::{Certificate, PrivateKey};

use crate::error::Error;

pub fn generate_keys() -> Result<PKey<Private>, Error> {
	let rsa = Rsa::generate(2048)?;
	let privkey = PKey::from_rsa(rsa)?;
	Ok(privkey)
}

pub fn make_ca_cert(privkey: &PKeyRef<Private>, serial: u32) -> Result<X509, Error> {
	let mut x509_name = X509NameBuilder::new()?;
	x509_name.append_entry_by_text("CN", "Proxy")?;
	let x509_name = x509_name.build();

	let x509_serial = {
		let bn = BigNum::from_u32(serial)?;
		bn.to_asn1_integer()?
	};

	let x509_not_before = Asn1Time::days_from_now(0)?;
	let x509_not_after = Asn1Time::days_from_now(365)?;

	let mut x509 = X509Builder::new()?;
	x509.set_version(2)?;
	x509.set_serial_number(&x509_serial)?;
	x509.set_subject_name(&x509_name)?;
	x509.set_issuer_name(&x509_name)?;
	x509.set_pubkey(&privkey)?;
	x509.set_not_before(&x509_not_before)?;
	x509.set_not_after(&x509_not_after)?;
	x509.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
	x509.append_extension(SubjectKeyIdentifier::new().build(&x509.x509v3_context(None, None))?)?;
	x509.sign(&privkey, MessageDigest::sha256())?;
	let x509 = x509.build();
	Ok(x509)
}

pub fn save_cert(file: &str, cert: &X509Ref) -> Result<(), Error> {
	let mut file = File::create(file)?;
	file.write_all(&cert.to_pem()?)?;
	Ok(())
}

pub fn load_cert(file: &str) -> Result<X509, Error> {
	let mut file = File::open(file)?;
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	let cert = X509::from_pem(&bytes)?;
	Ok(cert)
}

pub fn save_key(file: &str, key: &PKeyRef<Private>) -> Result<(), Error> {
	let mut file = File::create(file)?;
	file.write_all(&key.private_key_to_pem_pkcs8()?)?;
	Ok(())
}

pub fn load_key(file: &str) -> Result<PKey<Private>, Error> {
	let mut file = File::open(file)?;
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	let key = PKey::private_key_from_pem(&bytes)?;
	Ok(key)
}

pub fn cert_cursor(cert: &X509Ref) -> Result<Cursor<Vec<u8>>, Error> {
	let buffer = cert.to_pem()?;
	Ok(Cursor::new(buffer))
}

pub fn key_cursor(key: &PKeyRef<Private>) -> Result<Cursor<Vec<u8>>, Error> {
	let buffer = key.private_key_to_pem_pkcs8()?;
	Ok(Cursor::new(buffer))
}

pub fn make_signed_cert(
	privkey: &PKeyRef<Private>,
	domain: &str,
	ca_privkey: &PKeyRef<Private>,
	ca_cert: &X509Ref,
	serial: u32,
) -> Result<X509, Error> {
	let mut x509_name = X509NameBuilder::new()?;
	x509_name.append_entry_by_text("CN", domain)?;
	let x509_name = x509_name.build();

	let x509_serial = {
		let bn = BigNum::from_u32(serial)?;
		bn.to_asn1_integer()?
	};

	let x509_not_before = Asn1Time::days_from_now(0)?;
	let x509_not_after = Asn1Time::days_from_now(365)?;

	let mut x509 = X509Builder::new()?;
	x509.set_version(2)?;
	x509.set_serial_number(&x509_serial)?;
	x509.set_subject_name(&x509_name)?;
	x509.set_issuer_name(ca_cert.subject_name())?;
	x509.set_pubkey(&privkey)?;
	x509.set_not_before(&x509_not_before)?;
	x509.set_not_after(&x509_not_after)?;
	x509.append_extension(
		SubjectAlternativeName::new()
			.dns(domain)
			.build(&x509.x509v3_context(Some(ca_cert), None))?,
	)?;
	x509.sign(&ca_privkey, MessageDigest::sha256())?;
	let x509 = x509.build();
	Ok(x509)
}

pub fn make_pkcs12(
	password: &str,
	name: &str,
	key: &PKeyRef<Private>,
	cert: &X509Ref,
) -> Result<Pkcs12, Error> {
	let pkcs12 = Pkcs12::builder().build(password, name, key, cert)?;
	Ok(pkcs12)
}

pub fn load_ca() -> Result<(PKey<Private>, X509), Error> {
	// let ca_privkey_ossl = generate_keys()?;
	// let ca_cert_ossl = make_ca_cert(&ca_privkey_ossl, rand::random::<u32>())?;
	// save_key("ca_key.pem", &ca_privkey_ossl)?;
	// save_cert("ca_cert.pem", &ca_cert_ossl)?;

	let ca_privkey_ossl = load_key("ca_key.pem")?;
	let ca_cert_ossl = load_cert("ca_cert.pem")?;

	Ok((ca_privkey_ossl, ca_cert_ossl))
}

pub fn convert_to_rustls(
	privkey: &PKey<Private>,
	cert: &X509,
) -> Result<(Vec<PrivateKey>, Vec<Certificate>), Error> {
	let mut privkey_cursor = key_cursor(&privkey)?;
	let privkey_tls = rustls::internal::pemfile::pkcs8_private_keys(&mut privkey_cursor)
		.map_err(|_| Error::RustlsEmptyErr)?;
	let mut cert_cursor = cert_cursor(&cert)?;
	let cert_tls =
		rustls::internal::pemfile::certs(&mut cert_cursor).map_err(|_| Error::RustlsEmptyErr)?;
	Ok((privkey_tls, cert_tls))
}
