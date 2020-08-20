// const PROXY_CREDS: &str = "qwer:qwer";

use futures::prelude::*;

use http_types::{Body, Request, Response};

use lol_html::{
	doc_text,
	html_content::{ContentType, TextType},
	HtmlRewriter, Settings,
};

use structopt::StructOpt;

use std::{net::SocketAddr, path::PathBuf};

use deeprox::{gen_key_and_cert, proxy::Proxy};

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
				if t.text_type() != TextType::Data {
					return Ok(());
				}
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
		Err(_) => {
			let body = Body::from_bytes(output);
			input.set_body(body);
			return Ok(input);
		}
	};
	match rewriter.end().map_err(|_| ()) {
		Ok(_) => (),
		Err(_) => {
			let body = Body::from_bytes(output);
			input.set_body(body);
			return Ok(input);
		}
	};

	let body = Body::from_bytes(output);
	input.set_body(body);
	Ok(input)
}

#[derive(StructOpt)]
struct GenerateOpt {
	#[structopt(short, default_value = "ca_key.pem")]
	key_path: PathBuf,

	#[structopt(short, default_value = "ca_cert.pem")]
	cert_path: PathBuf,
}

#[derive(StructOpt)]
struct ProxyOpt {
	#[structopt(default_value = "127.0.0.1:8080")]
	address: SocketAddr,

	#[structopt(short, default_value = "ca_key.pem")]
	key_path: PathBuf,

	#[structopt(short, default_value = "ca_cert.pem")]
	cert_path: PathBuf,
}

#[derive(StructOpt)]
enum Opt {
	Generate(GenerateOpt),
	Proxy(ProxyOpt),
}

#[async_std::main]
async fn main() {
	match Opt::from_args() {
		Opt::Generate(o) => gen_key_and_cert(&o.key_path, &o.cert_path).unwrap(),
		Opt::Proxy(o) => {
			let creds = None;
			let mut proxy = Proxy::new(o.address, creds, o.key_path, o.cert_path);
			proxy.edit_request_using(|r| modify_request(r).boxed());
			proxy.edit_response_using(|r| modify_response(r).boxed());
			proxy.start().await.unwrap();
		}
	};
}
