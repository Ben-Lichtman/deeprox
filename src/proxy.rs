use std::sync::Arc;

use async_std::net::{SocketAddr, TcpListener};
use async_std::task::spawn;

use http_types::{Request, Response};

use futures::future::BoxFuture;
use futures::prelude::*;

use crate::error::Error;
use crate::http::*;

pub struct Proxy {
	pub addr: SocketAddr,
	pub auth: Option<&'static str>,
	pub edit_request: fn(Request) -> BoxFuture<'static, Result<Request, Error>>,
	pub edit_response: fn(Response) -> BoxFuture<'static, Result<Response, Error>>,
}

async fn ident_request(input: Request) -> Result<Request, Error> { Ok(input) }

async fn ident_response(input: Response) -> Result<Response, Error> { Ok(input) }

impl Proxy {
	pub fn new(addr: SocketAddr, auth: Option<&'static str>) -> Self {
		Proxy {
			addr,
			auth,
			edit_request: |r| ident_request(r).boxed(),
			edit_response: |r| ident_response(r).boxed(),
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
