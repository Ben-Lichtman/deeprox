use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("something could not be parsed")]
	ParseErr,
	#[error("proxy client could not authenticate")]
	ProxyAuthErr,
	#[error("http transformer error")]
	TransformationErr,
	#[error(transparent)]
	OSSLErr(#[from] openssl::error::Error),
	#[error(transparent)]
	OSSLErrStack(#[from] openssl::error::ErrorStack),
	#[error(transparent)]
	IoErr(#[from] std::io::Error),
	#[error(transparent)]
	RustlsErr(#[from] rustls::TLSError),
	#[error("something went wrong in rustls")]
	RustlsEmptyErr,
	#[error("something went wrong in webpki")]
	WebPkiErr,
	#[error("something went wrong in http_types")]
	HttpTypeErr,
	#[error(transparent)]
	UTF8Err(#[from] std::str::Utf8Error),
	#[error("unknown error")]
	Unknown,
}
