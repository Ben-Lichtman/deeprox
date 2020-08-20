mod crypto_helpers;
mod http;

pub mod error;
pub mod proxy;

use std::path::Path;

use crate::{
	crypto_helpers::{generate_keys, make_ca_cert, save_cert, save_key},
	error::Error,
};

pub fn gen_key_and_cert(key_path: &Path, cert_path: &Path) -> Result<(), Error> {
	let ca_privkey_ossl = generate_keys()?;
	let ca_cert_ossl = make_ca_cert(&ca_privkey_ossl, rand::random::<u32>())?;
	save_key(key_path, &ca_privkey_ossl)?;
	save_cert(cert_path, &ca_cert_ossl)?;

	Ok(())
}
