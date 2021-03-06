use enochecker::async_trait;
use enochecker::result::{CheckerError, CheckerResult};
use enochecker::{run_checker, Checker, CheckerRequest};
use serde::{Deserialize, Serialize};

use mongodb::{
    bson::doc,
    options::{ClientOptions, ServerAddress},
    Client,
};

use tracing::{debug, info, trace_span, warn, Instrument};

struct ExampleChecker {
    db: Client,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExampleServiceUser {
    username: String,
    password: String,
    unique_id: String,
}

impl ExampleChecker {
    async fn new() -> Self {
        let client = Client::with_options(
            ClientOptions::builder()
                .hosts(vec![ServerAddress::Tcp {
                    host: "localhost".into(),
                    port: Some(27017),
                }])
                .build(),
        )
        .expect("Failed to establish mongo-client");

        for db_name in client
            .list_database_names(None, None)
            .await
            .expect("Mongo conn failed")
        {
            println!("{}", db_name);
        }

        ExampleChecker { db: client }
    }
}

#[async_trait]
impl Checker for ExampleChecker {
    const SERVICE_NAME: &'static str = "ExampleService";
    const FLAG_VARIANTS: u64 = 1;
    const NOISE_VARIANTS: u64 = 1;
    const HAVOC_VARIANTS: u64 = 1;
    const EXPLOIT_VARIANTS: u64 = 0;

    async fn putflag(&self, checker_request: &CheckerRequest) -> CheckerResult<()> {
        self.db
            .database("daw")
            .collection("dawdw")
            .insert_one(
                ExampleServiceUser {
                    username: "penis".to_owned(),
                    password: "1234".to_owned(),
                    unique_id: checker_request.task_chain_id.clone(),
                },
                None,
            )
            .await
            .expect("Database insert failed");
        Ok(())
    }

    async fn getflag(&self, checker_request: &CheckerRequest) -> CheckerResult<()> {
        let _foo: ExampleServiceUser = self
            .db
            .database("daw")
            .collection("dawdw")
            .find_one(doc! { "unique_id": &checker_request.task_chain_id }, None)
            .await
            .unwrap()
            .unwrap();
        Ok(())
    }

    async fn putnoise(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        // Tracing information https://docs.rs/tracing/
        async {
            debug!("Registration successful");
        }
        .instrument(trace_span!("REGISTER"))
        .await;
        // instrument async code

        trace_span!("LOGIN").in_scope(|| info!("LOGIN DEBUG-PRINT")); // use in_scope only for syncronous subsections

        warn!("(WARN) PUTNOISE LOGGING");
        info!("(INFO) PUTNOISE LOGGING");
        debug!("(DBUG) PUTNOISE LOGGING");
        Ok(())
    }

    async fn getnoise(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        Err(CheckerError::Mumble("This is supposed to be a message that hopefully wraps when displayed on the checker-website. I hope <pre></pre> elements automagically add line breaks, since I don't know what I'll do if they don't D:."))
    }

    async fn havoc(&self, _checker_request: &CheckerRequest) -> CheckerResult<()> {
        Ok(())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    run_checker(ExampleChecker::new().await, 19321).await
}
