use std::sync::Arc;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

use async_std::prelude::*;

use async_std::io::prelude::*;

use async_std::io::copy;
use async_std::net::{TcpListener, TcpStream};
use async_std::task::spawn;

use rustls::{Certificate, ClientConfig, NoClientAuth, PrivateKey, ServerConfig};

use async_tls::client::TlsStream as ClientTlsStream;
use async_tls::server::TlsStream as ServerTlsStream;
use async_tls::{TlsAcceptor, TlsConnector};

use deeprox::error::Error;
use deeprox::helpers::*;

use async_h1::client;
use async_h1::server;

use piper;

use http_types::{Body, Method, Request, Response};

fn load_ca() -> Result<(PKey<Private>, X509), Error> {
	// let ca_privkey_ossl = generate_keys()?;
	// let ca_cert_ossl = make_ca_cert(&ca_privkey_ossl, rand::random::<u32>())?;
	// save_key("ca_key.pem", &ca_privkey_ossl)?;
	// save_cert("ca_cert.pem", &ca_cert_ossl)?;

	let ca_privkey_ossl = load_key("ca_key.pem")?;
	let ca_cert_ossl = load_cert("ca_cert.pem")?;

	Ok((ca_privkey_ossl, ca_cert_ossl))
}

fn convert_to_rustls(
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

fn make_server_config(domain: &str) -> Result<ServerConfig, Error> {
	// Load certificates
	let (ca_privkey_ossl, ca_cert_ossl) = load_ca()?;

	let domain_privkey_ossl = generate_keys()?;
	let domain_cert_ossl = make_signed_cert(
		&domain_privkey_ossl,
		domain,
		&ca_privkey_ossl,
		&ca_cert_ossl,
		rand::random::<u32>(),
	)?;
	let (mut domain_privkey_tls, domain_cert_tls) =
		convert_to_rustls(&domain_privkey_ossl, &domain_cert_ossl)?;

	let mut server_config = ServerConfig::new(NoClientAuth::new());
	server_config.set_single_cert(domain_cert_tls, domain_privkey_tls.remove(0))?;

	Ok(server_config)
}

async fn do_tls_handshake(
	mut client_stream: TcpStream,
	request: Request,
) -> Result<
	(
		piper::Arc<piper::Mutex<ServerTlsStream<TcpStream>>>,
		piper::Arc<piper::Mutex<ClientTlsStream<TcpStream>>>,
	),
	Error,
> {
	let mut info = request.host().unwrap().split(':');
	let host = info.next().unwrap();
	let _port = str::parse::<u16>(info.next().unwrap()).unwrap();

	// Open connection to server
	// println!("Connecting https: {}", request.host().unwrap());
	let server_stream = TcpStream::connect(request.host().unwrap()).await?;

	let mut client_config = ClientConfig::new();
	client_config
		.root_store
		.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
	let connector = TlsConnector::from(Arc::new(client_config));
	let server_stream = connector.connect(host, server_stream).await?;

	// Finish handshake with client
	client_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;

	// Start TCP Proxy
	let server_config = make_server_config(host)?;
	let client_stream = TlsAcceptor::from(Arc::new(server_config))
		.accept(client_stream)
		.await?;

	let (client_stream, server_stream) = (
		piper::Arc::new(piper::Mutex::new(client_stream)),
		piper::Arc::new(piper::Mutex::new(server_stream)),
	);

	Ok((client_stream, server_stream))
}

async fn read_request(
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<Option<Request>, Error> {
	server::decode(client_stream)
		.await
		.map_err(|_| Error::HttpTypeErr)
}

async fn read_response(
	server_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<Response, Error> {
	client::decode(server_stream)
		.await
		.map_err(|_| Error::HttpTypeErr)
}

async fn edit_request(mut input: Request) -> Result<Request, Error> {
	let body = input.take_body();
	let body_bytes = body.into_bytes().await.map_err(|_| Error::HttpTypeErr)?;
	// println!("Request: {:?}", &input);
	// println!("Request body: {}", String::from_utf8_lossy(&body_bytes));
	let body = Body::from_bytes(body_bytes);
	input.set_body(body);
	Ok(input)
}

async fn edit_response(mut input: Response) -> Result<Response, Error> {
	let body = input.take_body();
	let body_bytes = body.into_bytes().await.map_err(|_| Error::HttpTypeErr)?;
	// println!("Response: {:?}", &input);
	// println!("Response body: {}", String::from_utf8_lossy(&body_bytes));
	let body = Body::from_bytes(body_bytes);
	input.set_body(body);
	Ok(input)
}

async fn handle_request(
	request: Request,
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
	server_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<(), Error> {
	let request = edit_request(request).await?;
	let request_encoded = client::Encoder::encode(request)
		.await
		.map_err(|_| Error::HttpTypeErr)?;
	copy(request_encoded, server_stream.clone()).await?;
	let response = read_response(server_stream).await?;
	let response = edit_response(response).await?;
	let response_encoded = server::Encoder::new(response);
	copy(response_encoded, client_stream).await?;
	Ok(())
}

async fn enter_loop(
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
	server_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<(), Error> {
	loop {
		let request = match read_request(client_stream.clone()).await? {
			Some(r) => r,
			None => break Ok(()),
		};
		handle_request(request, client_stream.clone(), server_stream.clone()).await?;
	}
}

async fn handle_connection(client_stream: TcpStream) -> Result<(), Error> {
	let request = read_request(client_stream.clone()).await?.unwrap();

	if request.method() == Method::Connect {
		let (tls_client_stream, tls_server_stream) =
			do_tls_handshake(client_stream, request).await?;
		enter_loop(tls_client_stream, tls_server_stream).await?;
	}
	else {
		let addr = request.url().socket_addrs(|| Some(80)).unwrap()[0];
		// println!("Connecting http: {}", &addr);
		let server_stream = TcpStream::connect(&addr).await?;
		handle_request(request, client_stream.clone(), server_stream.clone()).await?;
		enter_loop(client_stream, server_stream).await?;
	}

	Ok(())
}

#[async_std::main]
async fn main() -> Result<(), Error> {
	let listener = TcpListener::bind("127.0.0.1:8080").await?;

	loop {
		let (stream, _peer_addr) = listener.accept().await?;
		spawn(handle_connection(stream));
	}
}
