use async_std::{
	net::{SocketAddr, TcpListener},
	task::spawn,
};

use http_types::{Request, Response};

use futures::{future::BoxFuture, prelude::*};

use std::{path::PathBuf, sync::Arc};

use crate::{error::Error, http::*};

pub struct Proxy {
	pub addr: SocketAddr,
	pub auth: Option<&'static str>,
	pub key: PathBuf,
	pub cert: PathBuf,
	pub edit_request: fn(Request) -> BoxFuture<'static, Result<Request, ()>>,
	pub edit_response: fn(Response) -> BoxFuture<'static, Result<Response, ()>>,
}

async fn ident_request(input: Request) -> Result<Request, ()> { Ok(input) }

async fn ident_response(input: Response) -> Result<Response, ()> { Ok(input) }

impl Proxy {
	pub fn new(addr: SocketAddr, auth: Option<&'static str>, key: PathBuf, cert: PathBuf) -> Self {
		Proxy {
			addr,
			auth,
			key,
			cert,
			edit_request: |r| ident_request(r).boxed(),
			edit_response: |r| ident_response(r).boxed(),
		}
	}

	pub fn edit_request_using(
		&mut self,
		f: fn(Request) -> BoxFuture<'static, Result<Request, ()>>,
	) {
		self.edit_request = f;
	}

	pub fn edit_response_using(
		&mut self,
		f: fn(Response) -> BoxFuture<'static, Result<Response, ()>>,
	) {
		self.edit_response = f;
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
