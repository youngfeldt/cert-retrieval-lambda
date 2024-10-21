// Certificate Retrieval Service
// Component # 4 in this Architecture:
//  <Confluence Link here >
// Todo:
// 1. Read Environment Variable to get 
//    a. [Done] Secret ID
//    b. [pending] List of PCR8 values.  Pending product update.
// 2. [Pending] Validate Attestation Doc
//    a. Get PCR values and compare PCR8 to env var. list of allowed PCR8 values.
// 3. [Done] Retrieve Secret
// 4. [Done] Retrieve contents of S3 object
// 5. [Pending] Decode & Decrypt passphrase
// 6. [Pending] Validate Attestation Document
//    Test this crate: https://docs.rs/attestation-doc-validation/0.9.0/attestation_doc_validation/index.html
// 7. [Pending] Clean up code, catching all errors and loggging appropriately.
// 8. [Pending] Ensure comment and documentation coverage.
//
// Processing
// 1. Check PCR8 value is member of approved list or Deny/Exit
// 2. Validate attestation document or Deny/Exit
// 3. Retreive p12 keystore, and passphrase.  Decrypt passphase with recipient and return all.
//================================================================================================================
use aws_config::meta::region::RegionProviderChain;
use aws_config::{self, BehaviorVersion, SdkConfig};
use lambda_runtime::{run, service_fn, LambdaEvent};
use std::env;

// use aws_sdk_kms::Client as KMSClient;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use simple_logger::SimpleLogger;

#[derive(Deserialize, Serialize)] // Add Serialize here
struct Request {
    attestation_doc: String,
}
#[derive(Serialize)]
struct Response {
    invoked_function_arn: String,
    env_config: String,
    attestation_doc: String,
    json_env: String,
    mtls_secret_arn: String,
    secret_value: Value,
    enc_p12_keystore: String,
}

// Todo #1  Read environment variables
fn get_lambda_env_var() -> Result<Value, lambda_runtime::Error> {
    // Get environment variables; for now, just MTLS cert secret ID.
    // Enhance to also get PCR8 value list.
    let json_environment = env::var("JSON_ENVIRONMENT")
        .map_err(|_| lambda_runtime::Error::from("$JSON_ENVIRONMENT is not set"))?;

    let json_val: Value = serde_json::from_str(&json_environment)
        .map_err(|e| lambda_runtime::Error::from(format!("Invalid JSON: {}", e)))?;

    Ok(json_val)
}

// Todo #2 Validate Attestation Document
async fn validate_attestation_doc(attestation_doc: &str) -> Result<(), lambda_runtime::Error> {
    // Validate attestation document
    // 1. Check that PCR8 value is one of the approved.
    // 2. Validate attestation document with attestation_doc_validation crate.
    todo!("Validate PCR8 value in attestation document against accepted values in Environment Variable.");
    todo!("Validate attestation document");
}

// Todo #3  Retrieve secret from secrets manager.
async fn get_secret(config: &SdkConfig, arn: &str) -> Result<Value, lambda_runtime::Error> {
    let client = SecretsManagerClient::new(&config);

    let resp = client
        .get_secret_value()
        .secret_id(arn)
        .send()
        .await
        .map_err(|e| lambda_runtime::Error::from(format!("Failed to retrieve secret: {}", e)))?;

    let secret_value = resp.secret_string().unwrap_or("No value!");
    let json_secret_value: Value = serde_json::from_str(&secret_value)
        .map_err(|e| lambda_runtime::Error::from(format!("Invalid JSON: {}", e)))?;

    // Ok(secret_value.to_string())
    Ok(json_secret_value)
}

// Todo #4  Retrieve contents from S3.
async fn get_contents(config: &SdkConfig, s3_uri: &str) -> Result<String, lambda_runtime::Error> {
    let parts: Vec<&str> = s3_uri.split('/').collect();
    let bucket = parts[2];
    let key = parts[3..].join("/");

    let client = S3Client::new(&config);

    info!("Bucket: {}  Key: {}  -- attempting get.", &bucket, &key);

    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| lambda_runtime::Error::from(format!("Failed to retrieve object: {}", e)))?;

    let body = resp.body.collect().await?;
    let body_bytes = body.into_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    println!("{}", body_str);

    Ok(body_str.to_string())
}

// Todo: #5 decrypt data with kms
async fn decrypt_value(data: &String) -> Result<Response, lambda_runtime::Error> {
    todo!("Take value provided and decrypt with --recipient <attestation_doc>")
}

// ============ Function Handler ====================================================================
async fn function_handler(event: LambdaEvent<Request>) -> Result<Response, lambda_runtime::Error> {

    info!( "Processing event: {}", serde_json::to_string_pretty(&event.payload).unwrap());

    // Get some context about the function
    let env_config_str = format!("{:?}", &event.context.env_config);
    let invoked_function_arn = event.context.invoked_function_arn;

    // Get parameter
    let attestation_doc = event.payload.attestation_doc;

    // Get Lambda Environment variables to find MTLS Client Cert Secret
    let lambda_environment_vars = get_lambda_env_var()?;

    info!("Lambda Environment Vars: {}", serde_json::to_string_pretty(&lambda_environment_vars).unwrap());

    let mtls_secret_arn = lambda_environment_vars["MTLS_SECRET_ARN"]
        .as_str()
        .ok_or_else(|| lambda_runtime::Error::from("MTLS_SECRET_ARN is missing from Environment Variables"))?;

    let enclave_signer_pcr8 = lambda_environment_vars["ENCLAVE_SIGNER"]
        .as_str()
        .ok_or_else(|| lambda_runtime::Error::from("ENCLAVE_SIGNER is missing from Environment Variables"))?;

    // Setup AWS Config
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(region_provider)
        .load()
        .await;

    // Get Secret
    let secret_value = get_secret(&config, mtls_secret_arn).await?;

    // Get Keystore.p12 from Secret
    // let keystore_p12 = secret_value["keystore.p12"].as_str().unwrap_or("No value!");

    let enc_p12_keystore = get_contents(
        &config,
        secret_value["p12_keystore_s3_uri"]
            .as_str()
            .ok_or_else(|| lambda_runtime::Error::from("Invalid S3 URI"))?,
    )
    .await?;

    let resp = Response {
        invoked_function_arn: invoked_function_arn,
        env_config: env_config_str,
        attestation_doc,
        json_env: lambda_environment_vars.to_string(), // Use the result from `get_lambda_env_var`
        mtls_secret_arn: mtls_secret_arn.to_string(),
        secret_value: secret_value,
        enc_p12_keystore: enc_p12_keystore,
    };

    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();
    info!("THIS IS AN EXAMPLE INFO MESSAGE.");
    warn!("This is an example warning message.");

    run(service_fn(function_handler)).await
}
