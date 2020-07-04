use async_std::net::{TcpListener, ToSocketAddrs};
use async_std::task::spawn;

use crate::error::Error;
use crate::http::*;

pub struct Proxy<T: ToSocketAddrs> {
	addr: T,
	auth: Option<&'static str>,
}

impl<T: ToSocketAddrs> Proxy<T> {
	pub fn new(addr: T, auth: Option<&'static str>) -> Self { Proxy { addr, auth } }

	pub async fn start(&self) -> Result<(), Error> {
		let listener = TcpListener::bind(&self.addr).await?;

		loop {
			let (stream, _peer_addr) = listener.accept().await?;
			spawn(handle_connection(stream, self.auth));
		}
	}
}
