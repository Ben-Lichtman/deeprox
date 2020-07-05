use std::sync::Arc;

use async_std::prelude::*;

use async_std::io::prelude::*;

use async_std::io::copy;
use async_std::net::TcpStream;

use rustls::{ClientConfig, NoClientAuth, ServerConfig};

use async_tls::client::TlsStream as ClientTlsStream;
use async_tls::server::TlsStream as ServerTlsStream;
use async_tls::{TlsAcceptor, TlsConnector};

use async_h1::{client, server};

use http_types::{Method, Request, Response, StatusCode};

use crate::crypto_helpers::*;
use crate::error::Error;
use crate::proxy::Proxy;

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
		async_dup::Arc<async_dup::Mutex<ServerTlsStream<TcpStream>>>,
		async_dup::Arc<async_dup::Mutex<ClientTlsStream<TcpStream>>>,
	),
	Error,
> {
	let url = request.url();
	// dbg!(&url);
	let socket_addr = url.socket_addrs(|| Some(80))?;
	let host_str = url.host_str().unwrap();

	// Open connection to server
	let server_stream = TcpStream::connect(socket_addr.as_slice()).await?;

	let mut client_config = ClientConfig::new();
	client_config
		.root_store
		.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
	let connector = TlsConnector::from(Arc::new(client_config));
	let server_stream = connector.connect(host_str, server_stream).await?;

	// Finish handshake with client
	client_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;

	// Start TCP Proxy
	let server_config = make_server_config(host_str)?;
	let client_stream = TlsAcceptor::from(Arc::new(server_config))
		.accept(client_stream)
		.await?;

	let (client_stream, server_stream) = (
		async_dup::Arc::new(async_dup::Mutex::new(client_stream)),
		async_dup::Arc::new(async_dup::Mutex::new(server_stream)),
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

async fn handle_request(
	proxy: Arc<Proxy>,
	request: Request,
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
	server_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<(), Error> {
	let request = (proxy.edit_request)(request).await?;
	let method = request.method();
	let request_encoded = client::Encoder::encode(request)
		.await
		.map_err(|_| Error::HttpTypeErr)?;
	copy(request_encoded, server_stream.clone()).await?;
	let response = read_response(server_stream).await?;
	let response = (proxy.edit_response)(response).await?;
	let response_encoded = server::Encoder::new(response, method);
	copy(response_encoded, client_stream).await?;
	Ok(())
}

async fn enter_loop(
	proxy: Arc<Proxy>,
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
	server_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
) -> Result<(), Error> {
	loop {
		let request = match read_request(client_stream.clone()).await? {
			Some(r) => r,
			None => break Ok(()),
		};
		handle_request(
			proxy.clone(),
			request,
			client_stream.clone(),
			server_stream.clone(),
		)
		.await?;
	}
}

async fn proxy_auth(
	client_stream: impl Read + Write + Clone + Send + Sync + Unpin + 'static,
	creds: &str,
) -> Result<Request, Error> {
	let mut response = Response::new(StatusCode::ProxyAuthenticationRequired);
	response.append_header("Proxy-Authenticate", "Basic");
	let response_encoded = server::Encoder::new(response, Method::Connect);
	copy(response_encoded, client_stream.clone()).await?;
	let request = match read_request(client_stream).await? {
		Some(r) => r,
		None => return Err(Error::Unknown),
	};
	let given_creds = request.header("proxy-authorization").unwrap();
	if given_creds != &format!("Basic {}", base64::encode(creds)) {
		return Err(Error::ProxyAuthErr);
	}
	// dbg!(&request);
	Ok(request)
}

pub async fn handle_connection(proxy: Arc<Proxy>, client_stream: TcpStream) -> Result<(), Error> {
	let request = match read_request(client_stream.clone()).await? {
		Some(r) => r,
		None => return Ok(()),
	};

	let request = match proxy.auth {
		Some(s) => proxy_auth(client_stream.clone(), s).await?,
		None => request,
	};

	if request.method() == Method::Connect {
		let (tls_client_stream, tls_server_stream) =
			do_tls_handshake(client_stream, request).await?;
		enter_loop(proxy, tls_client_stream, tls_server_stream).await?;
	}
	else {
		let addr = request.url().socket_addrs(|| Some(80)).unwrap()[0];
		// println!("Connecting http: {}", &addr);
		let server_stream = TcpStream::connect(&addr).await?;
		handle_request(
			proxy.clone(),
			request,
			client_stream.clone(),
			server_stream.clone(),
		)
		.await?;
		enter_loop(proxy, client_stream, server_stream).await?;
	}

	Ok(())
}
