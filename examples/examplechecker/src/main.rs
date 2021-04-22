use enochecker::{checker_app, Checker, CheckerError, CheckerRequest, CheckerResult};

use actix_web::HttpServer;
use async_trait::async_trait;

struct ExampleChecker;

#[async_trait]
impl Checker for ExampleChecker {
    const SERVICE_NAME: &'static str = "ExampleService";
    const FLAG_VARIANTS: u64 = 1;
    const NOISE_VARIANTS: u64 = 1;
    const HAVOC_VARIANTS: u64 = 1;

    async fn putflag(checker_request: &CheckerRequest) -> CheckerResult {
        Ok(())
    }

    async fn getflag(checker_request: &CheckerRequest) -> CheckerResult {
        Ok(())
    }

    async fn putnoise(checker_request: &CheckerRequest) -> CheckerResult {
        Ok(())
    }

    async fn getnoise(checker_request: &CheckerRequest) -> CheckerResult {
        Err(CheckerError::Mumble("This is supposed to be a message that hopefully wraps when displayed on the checker-website. I hope <pre></pre> elements automagically add line breaks, since I don't know what I'll do if they don't D:."))
    }

    async fn havoc(checker_request: &CheckerRequest) -> CheckerResult {
        Ok(())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| checker_app!(ExampleChecker))
        .bind("0.0.0.0:3031")?
        .run()
        .await
}
