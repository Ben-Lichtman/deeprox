use std::sync::Arc;

use async_std::net::{SocketAddr, TcpListener};
use async_std::task::spawn;

use http_types::{Request, Response};

use crate::error::Error;
use crate::http::*;

pub struct Proxy {
	pub addr: SocketAddr,
	pub auth: Option<&'static str>,
	pub edit_request: fn(Request) -> Result<Request, Error>,
	pub edit_response: fn(Response) -> Result<Response, Error>,
}

fn ident_request(input: Request) -> Result<Request, Error> { Ok(input) }

fn ident_response(input: Response) -> Result<Response, Error> { Ok(input) }

impl Proxy {
	pub fn new(addr: SocketAddr, auth: Option<&'static str>) -> Self {
		Proxy {
			addr,
			auth,
			edit_request: ident_request,
			edit_response: ident_response,
		}
	}

	pub async fn start(self) -> Result<(), Error> {
		let listener = TcpListener::bind(&self.addr).await?;

		let s = Arc::new(self);

		loop {
			let (stream, _peer_addr) = listener.accept().await?;
			spawn(handle_connection(s.clone(), stream));
		}
	}
}
