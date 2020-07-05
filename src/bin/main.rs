const PROXY_CREDS: &str = "qwer:qwer";

use futures::prelude::*;

use http_types::{Request, Response};

use deeprox::error::Error;
use deeprox::proxy::Proxy;

async fn ident_request(input: Request) -> Result<Request, Error> { Ok(input) }

async fn ident_response(input: Response) -> Result<Response, Error> { Ok(input) }

#[async_std::main]
async fn main() {
	let creds = None;
	let mut proxy = Proxy::new("0.0.0.0:8080".parse().unwrap(), creds);
	proxy.edit_request_using(|r| ident_request(r).boxed());
	proxy.edit_response_using(|r| ident_response(r).boxed());
	proxy.start().await.unwrap();
}
