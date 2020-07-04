const PROXY_CREDS: &str = "qwer:qwer";

use deeprox::proxy::Proxy;

#[async_std::main]
async fn main() {
	let proxy = Proxy::new("0.0.0.0:8080", Some(PROXY_CREDS));
	proxy.start().await.unwrap();
}
