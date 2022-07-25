use std::{pin::Pin, sync::Arc, time::Duration};

use actix_web::{web, App, HttpResponse, HttpServer};

use serde::{Deserialize, Serialize};

use tokio::time::timeout;

use tracing::{error_span, field, Instrument};

pub mod enologmessage_formatting_layer;
pub mod result;
use result::{CheckerError, CheckerResult};

pub use actix_web;
pub use async_trait::async_trait;
pub use tokio;

#[async_trait]
pub trait Checker: Sync + Send + 'static {
    const SERVICE_NAME: &'static str;
    const FLAG_VARIANTS: u64;
    const NOISE_VARIANTS: u64;
    const HAVOC_VARIANTS: u64;
    const EXPLOIT_VARIANTS: u64;

    // PUTFLAG/GETFLAG are required
    async fn putflag(&self, checker_request: &CheckerRequest) -> CheckerResult<Option<String>>;
    async fn getflag(&self, checker_request: &CheckerRequest) -> CheckerResult<()>;

    async fn putnoise(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn getnoise(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn havoc(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }

    async fn exploit(&self, _checker_request: &CheckerRequest) -> CheckerResult<String> {
        unimplemented!(
            "{:?} requested, but method is not implemented!",
            stringify!($func_name)
        );
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    service_name: &'static str,
    flag_variants: u64,
    noise_variants: u64,
    havoc_variants: u64,
    exploit_variants: u64,
}

async fn service_info<C>() -> web::Json<ServiceInfo>
where
    C: Checker,
{
    web::Json(ServiceInfo {
        service_name: C::SERVICE_NAME,
        flag_variants: C::FLAG_VARIANTS,
        noise_variants: C::NOISE_VARIANTS,
        havoc_variants: C::HAVOC_VARIANTS,
        exploit_variants: C::EXPLOIT_VARIANTS,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckerRequest {
    pub task_id: u64,
    pub method: String,
    pub address: String,
    pub team_id: u64,
    pub team_name: String,
    pub current_round_id: u64,
    pub related_round_id: u64,
    pub flag: Option<String>,
    pub variant_id: u64,
    pub timeout: u64,      // Timeout in ms
    pub round_length: u64, // Round Length in ms
    pub task_chain_id: String,

    // EXPLOIT SPECIFIC FIELDS
    pub flag_regex: Option<String>,
    pub flag_hash: Option<String>,
    pub attack_info: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CheckerResponse {
    result: String,
    message: Option<String>,
    flag: Option<String>,
    attack_info: Option<String>,
}

impl CheckerResponse {
    pub fn with_flag(self, flag: Option<String>) -> Self {
        Self { flag, ..self }
    }

    pub fn with_hint(self, flag_hint: Option<String>) -> Self {
        Self { attack_info: flag_hint, ..self }
    }
}

impl From<CheckerResult<()>> for CheckerResponse {
    fn from(result: CheckerResult<()>) -> Self {
        match result {
            Ok(()) => CheckerResponse {
                result: "OK".to_owned(),
                message: None,
                attack_info: None,
                flag: None,
            },
            Err(CheckerError::Mumble(msg)) => CheckerResponse {
                result: "MUMBLE".to_owned(),
                message: Some(msg.to_owned()),
                attack_info: None,
                flag: None,
            },

            Err(CheckerError::Offline(msg)) => CheckerResponse {
                result: "OFFLINE".to_owned(),
                message: Some(msg.to_owned()),
                attack_info: None,
                flag: None,
            },

            Err(CheckerError::InternalError(msg)) => CheckerResponse {
                result: "INTERNAL_ERROR".to_owned(),
                message: Some(msg.to_owned()),
                attack_info: None,
                flag: None,
            },
        }
    }
}

async fn check<C: Checker>(
    checker_request: web::Json<CheckerRequest>,
    checker: web::Data<Arc<C>>,
) -> web::Json<CheckerResponse> {
    let check_span = tracing::error_span!(
        "Running Check",
        method = checker_request.method.as_str(),
        taskId = checker_request.task_id,
        teamId = checker_request.team_id,
        teamName = checker_request.team_name.as_str(),
        currentRoundId = checker_request.current_round_id,
        relatedRoundId = checker_request.related_round_id,
        flag = field::Empty,
        variantId = checker_request.variant_id,
        taskChainId = checker_request.task_chain_id.as_str(),
    );

    if let Some(flag) = checker_request.flag.as_ref() {
        check_span.record("flag", &flag.as_str());
    }

    let mut flag_hint = None;
    let mut flag: Option<String> = None;
    let checker_result_fut = match checker_request.method.as_str() {
        "putflag" => {
            let res: Pin<Box<dyn futures::Future<Output = Result<(), CheckerError>> + Send>> =
                Box::pin(async {
                    let res = checker.putflag(&checker_request).await;

                    match res {
                        Ok(flag_hint_result) => {
                            flag_hint = flag_hint_result;
                            Ok(())
                        }
                        Err(v) => Err(v),
                    }
                });
            res.instrument(error_span!(parent: &check_span, "PUTFLAG"))
        }
        "getflag" => checker
            .getflag(&checker_request)
            .instrument(error_span!(parent: &check_span, "GETFLAG")),
        "putnoise" => checker
            .putnoise(&checker_request)
            .instrument(error_span!(parent: &check_span, "PUTNOISE")),
        "getnoise" => checker
            .getnoise(&checker_request)
            .instrument(error_span!(parent: &check_span, "GETNOISE")),
        "havoc" => checker
            .havoc(&checker_request)
            .instrument(error_span!(parent: &check_span, "HAVOC")),
        "exploit" => {
            let res: Pin<Box<dyn futures::Future<Output = Result<(), CheckerError>> + Send>> =
                Box::pin(async {
                    let _res = checker.exploit(&checker_request).await;

                    match _res {
                        Ok(val) => {
                            flag = Some(val);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                });
            res.instrument(error_span!(parent: &check_span, "EXPLOIT"))
        }
        _ => {
            let fut: Pin<Box<dyn futures::Future<Output = Result<(), CheckerError>> + Send>> =
                Box::pin(async { Err(CheckerError::InternalError("Invalid method")) });
            fut.instrument(error_span!(parent: &check_span, "INVALID!"))
        }
    }
    .instrument(check_span);

    let checker_result: CheckerResult<()> = match timeout(
        Duration::from_millis(checker_request.timeout),
        checker_result_fut,
    )
    .await
    {
        Ok(checker_result) => checker_result,
        Err(_) => Err(CheckerError::Mumble("Checker-Timeout!")),
    };

    web::Json(
        CheckerResponse::from(checker_result)
            .with_flag(flag)
            .with_hint(flag_hint),
    )
}

async fn request_form<C: Checker>() -> HttpResponse {
    HttpResponse::Ok().body(include_str!("post.html"))
}

// fn handle_json_error(err: &JsonPayloadError) -> actix_web::Error {
//     match err {
//         JsonPayloadError::Overflow => HttpResponse::PayloadTooLarge(),
//         _ => HttpResponse::BadRequest(),
//     }
//     .body(err.to_string())
//     .into()
// }

/// Starts the Checker on the given port
///
/// # Arguments
///
/// * `checker` a instance of struct struct that implements the Checker-Trait
/// * `port`the port to be bound by the Checker-Webserver
///
/// # Errors
///
/// This Function retuns an Error if sometheing related to the `HttpServer` fails.
/// These mainly include requesting an invalid (or already occupied) port,
/// or a misconfiguration of the Actix runtime.
pub async fn run_checker<C: Checker>(checker: C, port: u16) -> std::io::Result<()> {
    //let _trace_subscriber = tracing_subscriber::fmt::SubscriberBuilder::default().json().try_init();
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let eno_formatter = crate::enologmessage_formatting_layer::EnoLogmessageFormat {
        tool: std::any::type_name::<C>(),
        service_name: C::SERVICE_NAME,
        flatten_event: true,
    };

    // let subscriber = Registry::default().with(eno_formatter);
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_writer(non_blocking_writer)
        .json()
        .event_format(eno_formatter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set logging subscriber");

    let checker = Arc::new(checker);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(checker.clone()))
            .app_data(web::JsonConfig::default().limit(4096))
            .route("/", web::post().to(check::<C>))
            .route("/", web::get().to(request_form::<C>))
            .route("/service", web::get().to(service_info::<C>))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

// #[cfg(test)]
// mod user_tests {
//     use super::{
//         Checker, CheckerError, CheckerRequest, CheckerResponse, CheckerResult,
//     };
//     use actix_web::http::Method;

//     use actix_web::{self, test};
//     use async_trait::async_trait;

//     use serde_json;
//     struct TestChecker;

//     #[async_trait]
//     impl Checker for TestChecker {
//         const SERVICE_NAME: &'static str = "TestService";
//         const FLAG_VARIANTS: u64 = 1;
//         const NOISE_VARIANTS: u64 = 1;
//         const HAVOC_VARIANTS: u64 = 1;

//         async fn putflag(&self, _checker_request: &CheckerRequest) -> CheckerResult {
//             println!("putflag");
//             Ok(())
//         }

//         async fn getflag(&self, _checker_request: &CheckerRequest) -> CheckerResult {
//             println!("getflag");
//             Err(CheckerError::Mumble("Flag was not able to be retrieved!"))
//         }

//         async fn havoc(&self, _checker_request: &CheckerRequest) -> CheckerResult {
//             println!("Havoc");
//             Ok(())
//         }
//     }

//     #[actix_web::main]
//     #[test]
//     async fn test_setup() {
//         let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;

//         let req = test::TestRequest::with_uri("/service").to_request();
//         let resp = test::call_service(&mut srv, req).await;

//         println!("{:?}", resp);
//         println!("{:?}", test::read_body(resp).await);
//     }

//     #[actix_web::main]
//     #[test]
//     async fn test_method_call() {
//         let mut srv = actix_web::test::init_service(checker_app!(TestChecker)).await;

//         let request_data = serde_json::to_string_pretty(&CheckerRequest {
//             run_id: 1,
//             method: "putflag".to_string(),
//             service_id: 1,
//             service_name: "ulululu".to_string(),
//             address: "127.0.0.1".to_string(),
//             flag: Some("ENOTESTFLAG".to_string()),
//             flag_index: 0,
//             round_id: 0,
//             related_round_id: 0,
//             timeout: 15000,
//             round_length: 60,
//             team_id: 1,
//             team_name: "TESTTEAM".to_string(),
//         });

//         let req = serde_json::to_string_pretty(&CheckerRequest {
//             run_id: 1,
//             method: "putflag".to_string(),
//             service_id: 1,
//             service_name: "ulululu".to_string(),
//             address: "127.0.0.1".to_string(),
//             flag: Some("ENOTESTFLAG".to_string()),
//             flag_index: 0,
//             round_id: 0,
//             related_round_id: 0,
//             timeout: 15000,
//             round_length: 60,
//             team_id: 1,
//             team_name: "TESTTEAM".to_string(),
//         })
//         .unwrap();
//         println!("{}", req);
//         let req = test::TestRequest::with_uri("/")
//             .method(Method::POST)
//             .set_json(&CheckerRequest {
//                 run_id: 1,
//                 method: "putflag".to_string(),
//                 service_id: 1,
//                 service_name: "ulululu".to_string(),
//                 address: "127.0.0.1".to_string(),
//                 flag: Some("ENOTESTFLAG".to_string()),
//                 flag_index: 0,
//                 round_id: 0,
//                 related_round_id: 0,
//                 timeout: 15000,
//                 round_length: 60,
//                 team_id: 1,
//                 team_name: "TESTTEAM".to_string(),
//             })
//             .to_request();

//         let resp = test::call_service(&mut srv, req).await;

//         println!("{:?}", resp);
//         println!("{:?}", test::read_body(resp).await);

//         let req = test::TestRequest::with_uri("/")
//             .method(Method::POST)
//             .set_json(&CheckerRequest {
//                 run_id: 1,
//                 method: "getflag".to_string(),
//                 service_id: 1,
//                 service_name: "ulululu".to_string(),
//                 address: "127.0.0.1".to_string(),
//                 flag: Some("ENOTESTFLAG".to_string()),
//                 flag_index: 0,
//                 round_id: 0,
//                 related_round_id: 0,
//                 timeout: 15000,
//                 round_length: 60,
//                 team_id: 1,
//                 team_name: "TESTTEAM".to_string(),
//             })
//             .to_request();

//         let resp = test::call_service(&mut srv, req).await;

//         println!("{:?}", resp);
//         let response_raw = test::read_body(resp).await;
//         println!("{:?}", response_raw);
//         let response: CheckerResponse =
//             serde_json::from_slice(&response_raw).expect("Failed to parse Response");
//         println!("{:?}", response);
//         assert_eq!(response.result, "MUMBLE");
//     }
// }
