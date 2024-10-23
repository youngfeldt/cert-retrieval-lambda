use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use hex;
// use log::{error, info, warn};
use log::info;
use reqwest;
use serde_json::Value;
use serde_json;
use std::io::Cursor;
use std::io::Read;
use zip::ZipArchive;

pub fn get_root_cert() -> Result<String, Box<dyn std::error::Error>> {
    let aws_root_cert_zip = reqwest::blocking::get("https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip")?
       .bytes()?;

    // Unzip the downloaded file to extract root.pem
    let reader = Cursor::new(aws_root_cert_zip);
    let mut zip = ZipArchive::new(reader)?;
    let mut root_pem_file = zip.by_name("root.pem")?;
    let mut aws_root_cert_pem = String::new();
    root_pem_file.read_to_string(&mut aws_root_cert_pem)?;

    // Check if the data contains the expected certificate format
    if !aws_root_cert_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err("Invalid AWS root certificate data received".into());
    }

    // Print the downloaded data to verify
    println!("Downloaded AWS Root Certificate PEM: {}", aws_root_cert_pem);

    Ok(aws_root_cert_pem)
}

pub fn parse_attestation_document(document: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    // Create a COSE Sign1 instance
    let cose = CoseSign1::from_bytes(document)?;
    
    // Decode the document to extract its payload
    let payload = cose.get_payload::<Openssl>(None)?;
    
    // Parse payload as CBOR
    let parsed_cbor: serde_cbor::Value = serde_cbor::from_slice(&payload)?;
    
    // Convert CBOR to JSON value
    let parsed_json = serde_json::to_value(convert_byte_arrays_to_hex(&parsed_cbor))?;
    // let json_string = serde_json::to_string_pretty(&parsed_json)?;
    // info!("Parsed CBOR to JSON: {}", json_string);

    Ok(parsed_json)
}

fn convert_byte_arrays_to_hex(value: &serde_cbor::Value) -> serde_cbor::Value {
    match value {
        serde_cbor::Value::Bytes(bytes) => serde_cbor::Value::Text(hex::encode(bytes)),
        serde_cbor::Value::Array(arr) => {
            serde_cbor::Value::Array(arr.iter().map(|v| convert_byte_arrays_to_hex(v)).collect())
        }
        serde_cbor::Value::Map(map) => {
            serde_cbor::Value::Map(map.iter().map(|(k, v)| (convert_byte_arrays_to_hex(k), convert_byte_arrays_to_hex(v))).collect())
        }
        _ => value.clone(),
    }
}
