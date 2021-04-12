use core::str;
use std::any::type_name;
use std::time::Duration;

use actix_web::{web, App, HttpServer};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

mod utils;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckerError {
    Mumble(&'static str),
    Offline(&'static str),
    InternalError,
}

pub type CheckerResult = Result<(), CheckerError>;

#[async_trait]
pub trait Checker {
    const FLAG_COUNT: u64;
    const NOISE_COUNT: u64;
    const HAVOC_COUNT: u64;

    async fn putflag() -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn getflag() -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn putnoise() -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn getnoise() -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn havoc() -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }
}

#[derive(Serialize, Debug)]
struct ServiceInfo {
    service_name: &'static str,
    flag_count: u64,
    noise_count: u64,
    havoc_count: u64,
}

async fn service_info<C>() -> web::Json<ServiceInfo>
where
    C: Checker,
{
    let body = web::Json(ServiceInfo {
        service_name: type_name::<C>(),
        flag_count: C::FLAG_COUNT,
        noise_count: C::NOISE_COUNT,
        havoc_count: C::HAVOC_COUNT,
    });

    body
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckerRequest {
    #[serde(rename="runId")]
    run_id: u64,
    method: String,
    address: String,
    #[serde(rename="serviceId")]
    service_id: u64,
    #[serde(rename="serviceName")]
    service_name: String,
    #[serde(rename="teamId")]
    team_id: u64,
    #[serde(rename="teamName")]
    team_name: String,
    #[serde(rename="roundId")]
    round_id: u64,
    #[serde(rename="relatedRoundId")]
    related_round_id: u64,
    flag: Option<String>,
    #[serde(rename="flagIndex")]
    flag_index: u64,
    timeout: u64,     // Timeout in miliseconds
    #[serde(rename="runId")]
    round_length: u64, // Round Length in seconds
}

#[derive(Serialize, Deserialize, Debug)]
struct CheckerResponse {
    result: String,
    message: Option<String>,
}

impl From<CheckerResult> for CheckerResponse {
    fn from(result: CheckerResult) -> Self {
        match result {
            Ok(()) => CheckerResponse {
                result: "OK".to_owned(),
                message: None,
            },
            Err(CheckerError::Mumble(msg)) => CheckerResponse {
                result: "MUMBLE".to_owned(),
                message: Some(msg.to_owned()),
            },

            Err(CheckerError::Offline(msg)) => CheckerResponse {
                result: "OFFLINE".to_owned(),
                message: Some(msg.to_owned()),
            },

            Err(CheckerError::InternalError) => CheckerResponse {
                result: "INTERNAL_ERROR".to_owned(),
                message: None,
            },
        }
    }
}

async fn check<C: Checker>(
    checker_request: web::Json<CheckerRequest>,
) -> web::Json<CheckerResponse> {
    let checker_result_fut = match checker_request.method.as_str() {
        "putflag" => C::putflag(),
        "getflag" => C::getflag(),
        "putnoise" => C::putnoise(),
        "getnoise" => C::getnoise(),
        "havoc" => C::havoc(),
        _ => {
            unimplemented!();
        }
    };

    let checker_result: CheckerResult = match timeout(
        Duration::from_millis(checker_request.timeout),
        checker_result_fut,
    )
    .await
    {
        Ok(checker_result) => checker_result,
        Err(_) => Err(CheckerError::Mumble("Checker-Timeout!")),
    };

    web::Json(CheckerResponse::from(checker_result))
}

pub async fn setup_checker<C>()
where
    C: Checker + 'static,
{
    let server = HttpServer::new(|| {
        App::new()
            .route("/service", web::get().to(service_info::<C>))
            .route("/", web::post().to(check::<C>))
    })
    .bind("0.0.0.0:3031")
    .expect("Failed to bind to socket")
    .run()
    .await;

    server.unwrap();
}

#[macro_export]
macro_rules! checker_app {
    ($C:ty) => {
        actix_web::App::new()
            .route(
                "/service",
                actix_web::web::get().to($crate::service_info::<$C>),
            )
            .route("/", actix_web::web::post().to($crate::check::<$C>))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::executor::block_on;

    struct TestChecker;

    #[async_trait]
    impl Checker for TestChecker {
        const FLAG_COUNT: u64 = 1;
        const NOISE_COUNT: u64 = 1;
        const HAVOC_COUNT: u64 = 1;

        async fn putflag() -> CheckerResult {
            println!("putflag");
            Ok(())
        }

        async fn getflag() -> CheckerResult {
            println!("getflag");
            panic!("GETFLAG_FAILED");
        }

        async fn havoc() -> CheckerResult {
            println!("Havoc");
            Ok(())
        }
    }

    #[test]
    fn test_service_info() {
        let info = block_on(service_info::<TestChecker>());
        println!("{:?}", &info);
    }
    #[test]
    fn test_ok_method() {
        assert_eq!(block_on(TestChecker::putflag()), Ok(()));
    }

    #[test]
    #[should_panic]
    fn test_panicing_method() {
        block_on(TestChecker::getflag());
    }

    #[test]
    #[should_panic]
    fn test_unimplemented_method() {
        block_on(TestChecker::putnoise());
    }

    #[test]
    fn test_stringify() {
        println!("{}", stringify!(CheckerResult::Mumble));
    }
}

#[cfg(test)]
mod user_tests {
    use super::{
        checker_app, Checker, CheckerError, CheckerRequest, CheckerResponse, CheckerResult,
    };
    use actix_web::http::Method;

    use actix_web::{self, test};
    use async_trait::async_trait;
    
    use serde_json;
    struct TestChecker;

    #[async_trait]
    impl Checker for TestChecker {
        const FLAG_COUNT: u64 = 1;
        const NOISE_COUNT: u64 = 1;
        const HAVOC_COUNT: u64 = 1;

        async fn putflag() -> CheckerResult {
            println!("putflag");
            Ok(())
        }

        async fn getflag() -> CheckerResult {
            println!("getflag");
            Err(CheckerError::Mumble("Flag was not able to be retrieved!"))
        }

        async fn havoc() -> CheckerResult {
            println!("Havoc");
            Ok(())
        }
    }

    #[actix_rt::test]
    async fn test_setup() {
        let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;

        let req = test::TestRequest::with_uri("/service").to_request();
        let resp = test::call_service(&mut srv, req).await;

        println!("{:?}", resp);
        println!("{:?}", test::read_body(resp).await);
    }

    #[actix_rt::test]
    async fn test_method_call() {
        let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;

        let req = test::TestRequest::with_uri("/")
            .method(Method::POST)
            .set_json(&CheckerRequest {
                run_id: 1,
                method: "putflag".to_string(),
                service_id: 1,
                service_name: "ulululu".to_string(),
                address: "127.0.0.1".to_string(),
                flag: Some("ENOTESTFLAG".to_string()),
                flag_index: 0,
                round_id: 0,
                related_round_id: 0,
                timeout: 15000,
                round_length: 60,
                team_id: 1,
                team_name: "TESTTEAM".to_string(),
            })
            .to_request();

        let resp = test::call_service(&mut srv, req).await;

        println!("{:?}", resp);
        println!("{:?}", test::read_body(resp).await);

        let req = test::TestRequest::with_uri("/")
            .method(Method::POST)
            .set_json(&CheckerRequest {
                run_id: 1,
                method: "getflag".to_string(),
                service_id: 1,
                service_name: "ulululu".to_string(),
                address: "127.0.0.1".to_string(),
                flag: Some("ENOTESTFLAG".to_string()),
                flag_index: 0,
                round_id: 0,
                related_round_id: 0,
                timeout: 15000,
                round_length: 60,
                team_id: 1,
                team_name: "TESTTEAM".to_string(),
            })
            .to_request();

        let resp = test::call_service(&mut srv, req).await;

        println!("{:?}", resp);
        let response_raw = test::read_body(resp).await;
        println!("{:?}", response_raw);
        let response: CheckerResponse = serde_json::from_slice(&response_raw).expect("Failed to parse Response");
        println!("{:?}", response);
        assert_eq!(response.result, "MUMBLE");
    }
}