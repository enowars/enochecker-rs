use enochecker::{Checker, CheckerRequest, CheckerResult, checker_app};

use async_trait::async_trait;
use actix_web::HttpServer;

struct ExampleChecker;

#[async_trait]
impl Checker for ExampleChecker {
    const SERVICE_NAME: &'static str = "ExampleService";
    const FLAG_COUNT: u64 = 1;
    const NOISE_COUNT: u64 = 1;
    const HAVOC_COUNT: u64 = 1;

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
        Ok(())
    }

    async fn havoc(checker_request: &CheckerRequest) -> CheckerResult {
        Ok(())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(||{
        checker_app!(ExampleChecker)
    }
    ).bind("0.0.0.0:3031")?.run().await
}
