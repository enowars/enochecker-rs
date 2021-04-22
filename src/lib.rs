use std::time::Duration;

use actix_web::{App, HttpResponse, HttpServer, error::JsonPayloadError, web};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckerError {
    Mumble(&'static str),
    Offline(&'static str),
    InternalError(&'static str),
}

pub type CheckerResult = Result<(), CheckerError>;

#[async_trait]
pub trait Checker {
    const SERVICE_NAME: &'static str;
    const FLAG_VARIANTS: u64;
    const NOISE_VARIANTS: u64;
    const HAVOC_VARIANTS: u64;

    // PUTFLAG/GETFLAG are required
    async fn putflag(checker_request: &CheckerRequest) -> CheckerResult;
    async fn getflag(checker_request: &CheckerRequest) -> CheckerResult;

    async fn putnoise(_checker_request: &CheckerRequest) -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn getnoise(_checker_request: &CheckerRequest) -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn havoc(_checker_request: &CheckerRequest) -> CheckerResult {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }
}

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Debug)]
pub struct ServiceInfo {
    service_name: &'static str,
    flag_variants: u64,
    noise_variants: u64,
    havoc_variants: u64,
}

pub async fn service_info<C>() -> web::Json<ServiceInfo>
where
    C: Checker,
{
    let body = web::Json(ServiceInfo {
        service_name: C::SERVICE_NAME,
        flag_variants: C::FLAG_VARIANTS,
        noise_variants: C::NOISE_VARIANTS,
        havoc_variants: C::HAVOC_VARIANTS,
    });

    body
}

#[serde(rename_all="camelCase")]
#[derive(Serialize, Deserialize, Debug)]
pub struct CheckerRequest {
    task_id: u64,
    method: String,
    address: String,
    team_id: u64,
    team_name: String,
    current_round_id: u64,
    related_round_id: u64,
    flag: Option<String>,
    variant_id: u64,
    timeout: u64,     // Timeout in miliseconds
    round_length: u64, // Round Length in seconds
    task_chain_id: String, // Round Length in seconds
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckerResponse {
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

            Err(CheckerError::InternalError(msg)) => CheckerResponse {
                result: "INTERNAL_ERROR".to_owned(),
                message: Some(msg.to_owned()),
            },
        }
    }
}

pub async fn check<C: Checker>(
    checker_request: web::Json<CheckerRequest>
) -> web::Json<CheckerResponse> {
    let checker_result_fut = match checker_request.method.as_str() {
        "putflag" => C::putflag(&checker_request),
        "getflag" => C::getflag(&checker_request),
        "putnoise" => C::putnoise(&checker_request),
        "getnoise" => C::getnoise(&checker_request),
        "havoc" => C::havoc(&checker_request),
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

pub async fn request_form<C>() -> HttpResponse
    where C: Checker {
    HttpResponse::Ok().body(include_str!("post.html"))
}

pub fn handle_json_error(err: JsonPayloadError) -> actix_web::Error {
    match err {
        JsonPayloadError::Overflow => HttpResponse::PayloadTooLarge(),
        _ => HttpResponse::BadRequest(),
    }.body(err.to_string()).into()
}

pub async fn setup_checker<C>()
where
    C: Checker + 'static,
{
    let server = HttpServer::new(|| {
        App::new()
            .route("/service", web::get().to(service_info::<C>))
            .route("/", web::post().to(check::<C>))
            .route("/", web::get().to(request_form::<C>))
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
            .app_data(
                actix_web::web::JsonConfig::default()
                    .limit(4096)
                    .error_handler(|err, req| {  // <- create custom error response
                        $crate::handle_json_error(err)
                    })
            )
            .route(
                "/service",
                actix_web::web::get().to($crate::service_info::<$C>),
            )
            .route("/", actix_web::web::post().to($crate::check::<$C>))
            .route("/", actix_web::web::get().to($crate::request_form::<$C>))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::executor::block_on;

    struct TestChecker;

    #[async_trait]
    impl Checker for TestChecker {
        const SERVICE_NAME: &'static str = "Test";
        const FLAG_COUNT: u64 = 1;
        const NOISE_COUNT: u64 = 1;
        const HAVOC_COUNT: u64 = 1;

        async fn putflag(_checker_request: &CheckerRequest) -> CheckerResult {
            println!("putflag");
            Ok(())
        }

        async fn getflag(_checker_request: &CheckerRequest) -> CheckerResult {
            println!("getflag");
            panic!("GETFLAG_FAILED");
        }

        async fn havoc(_checker_request: &CheckerRequest) -> CheckerResult {
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
        let req = CheckerRequest {
            task_id: 1,
            address: "127.0.0.1".to_string(),
            method: "putflag".to_string(),
            team_name: "ENOTESTTEAM".to_string(),
            team_id: 1,

            flag: Some("ENOTESTFLAG".to_string()),
            flag_index: 1,
            
            service_id: 0,
            service_name: "TestService".to_string(),

            round_id: 1,
            related_round_id: 1,

            round_length: 60,
            timeout: 15000,
        };
        assert_eq!(block_on(TestChecker::putflag(&req)), Ok(()));
    }

    #[test]
    #[should_panic]
    fn test_panicing_method() {
        let req = CheckerRequest {
            run_id: 1,
            address: "127.0.0.1".to_string(),
            method: "getflag".to_string(),
            team_name: "ENOTESTTEAM".to_string(),
            team_id: 1,

            flag: Some("ENOTESTFLAG".to_string()),
            flag_index: 1,
            
            service_id: 0,
            service_name: "TestService".to_string(),

            round_id: 1,
            related_round_id: 1,

            round_length: 60,
            timeout: 15000,
        };
        block_on(TestChecker::getflag(&req));
    }

    #[test]
    #[should_panic]
    fn test_unimplemented_method() {
        let req = CheckerRequest {
            run_id: 1,
            address: "127.0.0.1".to_string(),
            method: "putnoise".to_string(),
            team_name: "ENOTESTTEAM".to_string(),
            team_id: 1,

            flag: Some("ENOTESTFLAG".to_string()),
            flag_index: 1,
            
            service_id: 0,
            service_name: "TestService".to_string(),

            round_id: 1,
            related_round_id: 1,

            round_length: 60,
            timeout: 15000,
        };
        block_on(TestChecker::putnoise(&req));
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
        const SERVICE_NAME: &'static str = "TestService";
        const FLAG_COUNT: u64 = 1;
        const NOISE_COUNT: u64 = 1;
        const HAVOC_COUNT: u64 = 1;

        async fn putflag(_checker_request: &CheckerRequest) -> CheckerResult {
            println!("putflag");
            Ok(())
        }

        async fn getflag(_checker_request: &CheckerRequest) -> CheckerResult {
            println!("getflag");
            Err(CheckerError::Mumble("Flag was not able to be retrieved!"))
        }

        async fn havoc(_checker_request: &CheckerRequest) -> CheckerResult {
            println!("Havoc");
            Ok(())
        }
    }

    #[actix_web::main]
    #[test]
    async fn test_setup() {
        let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;

        let req = test::TestRequest::with_uri("/service").to_request();
        let resp = test::call_service(&mut srv, req).await;

        println!("{:?}", resp);
        println!("{:?}", test::read_body(resp).await);
    }

    #[actix_web::main]
    #[test]
    async fn test_method_call() {
        let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;
        
        let request_data = serde_json::to_string_pretty(&CheckerRequest {
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
        });

        let req = serde_json::to_string_pretty(&CheckerRequest {
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
        }).unwrap();
        println!("{}", req);
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
