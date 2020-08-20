// const PROXY_CREDS: &str = "qwer:qwer";

use futures::prelude::*;

use http_types::{Body, Request, Response};

use lol_html::{doc_text, html_content::ContentType, HtmlRewriter, Settings};

use deeprox::proxy::Proxy;

async fn modify_request(mut input: Request) -> Result<Request, ()> {
	// dbg!(&input);

	// let body_bytes = input.take_body().into_bytes().await.map_err(|_| ())?;

	let mut buffer = Vec::new();
	input.read_to_end(&mut buffer).await.map_err(|_| ())?;

	input.insert_header("accept-encoding", "indentity");

	let body = Body::from_bytes(buffer);
	input.set_body(body);

	// dbg!(&input);

	Ok(input)
}

async fn modify_response(mut input: Response) -> Result<Response, ()> {
	// dbg!(&input);

	// let body_bytes = input.take_body().into_bytes().await.map_err(|_| ())?;

	match input.content_type() {
		Some(m) => match m.essence() {
			"text/html" => (),
			_ => return Ok(input),
		},
		_ => return Ok(input),
	}

	let mut buffer = Vec::new();
	input.read_to_end(&mut buffer).await.map_err(|_| ())?;

	let mut output = Vec::new();
	let mut rewriter = HtmlRewriter::try_new(
		Settings {
			element_content_handlers: vec![],
			document_content_handlers: vec![doc_text!(|t| {
				let s = String::from(t.as_str());
				let s = s.replace("cloud", "fuck");
				let s = s.replace("Cloud", "Fuck");
				t.replace(&s, ContentType::Text);
				Ok(())
			})],
			..Settings::default()
		},
		|c: &[u8]| output.extend_from_slice(c),
	)
	.map_err(|_| ())?;

	match rewriter.write(&buffer).map_err(|_| ()) {
		Ok(_) => (),
		Err(_) => return Ok(input),
	};
	rewriter.end().map_err(|_| ())?;

	let body = Body::from_bytes(output);
	input.set_body(body);
	Ok(input)
}

#[async_std::main]
async fn main() {
	let creds = None;
	let mut proxy = Proxy::new(
		"127.0.0.1:8000".parse().unwrap(),
		creds,
		String::from("ca_key.pem"),
		String::from("ca_cert.pem"),
	);
	proxy.edit_request_using(|r| modify_request(r).boxed());
	proxy.edit_response_using(|r| modify_response(r).boxed());
	proxy.start().await.unwrap();
}
