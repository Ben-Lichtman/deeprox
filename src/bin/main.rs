const PROXY_CREDS: &str = "qwer:qwer";

use deeprox::proxy::Proxy;

#[async_std::main]
async fn main() {
	let proxy = Proxy::new("0.0.0.0:8080".parse().unwrap(), None);
	proxy.start().await.unwrap();
}
