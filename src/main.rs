mod login;
mod model;
mod response_utils;
mod encryptor;
mod register;

use cookie::Cookie;
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response, IntoResponse, http::Method};
use login::login;
use register::register;
use response_utils::{response_builder, internal_server_error_builder};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;
use rusoto_secretsmanager::{GetSecretValueRequest, SecretsManager, SecretsManagerClient};

use serde_json::{Value, json};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SecreteKeys {
    jwt_refresh: String,
    jwt_refresh_pub: String,
    jwt_access: String,
    jwt_access_pub: String
}

struct FuncContext<'a> {
    jwt_refresh_key: &'a EncodingKey,
    jwt_refresh_pub_key: &'a DecodingKey,
    jwt_access_key: &'a EncodingKey,
    client_dynamodb: &'a DynamoDbClient
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler<'a> (func_context: &'a FuncContext<'a>, event: Request) -> Result<Response<Body>, Error> {
    
    let body = event.body();

    let request_json: Value = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(_) => {
            let payload = json!({ "message" : "Invalid request body" });
            return Ok(response_builder(400, &payload)?);
        }
    };

    let refresh_token = match event.headers().get("Cookie") {
        Some(cookies) => {
            Cookie::split_parse(cookies.to_str().unwrap().to_string())
                .filter_map(|cookie| cookie.ok()) // Filter out any parsing errors
                .find(|cookie| cookie.name() == "refresh_token")
                .map(|cookie| cookie.value().to_string())
        }
        None => None,
    };

    match (event.method(), event.uri().path()) {
        (&Method::POST, "/main/auth/login" | "/main/auth/login/")
            => match login(&request_json, &func_context.client_dynamodb,&func_context.jwt_access_key, &func_context.jwt_refresh_key).await {
                Ok(res) => return Ok(res),
                Err(err) => return Ok(internal_server_error_builder(err.to_string())?)
            }
        (&Method::POST, "/main/auth/register" | "/main/auth/register/")
            => match register(&request_json, &func_context.client_dynamodb).await {
                Ok(res) => return Ok(res),
                Err(err) => return Ok(internal_server_error_builder(err.to_string())?)
            }
        (&Method::POST, "/main/auth/sign" | "/main/auth/sign/")
            => return Ok(response_builder(200, &json!({ "path" : event.uri().path() })) ?),
        (&Method::GET, "/main/auth/user" | "/main/auth/user/")
            => return Ok(response_builder(200, &json!({ "path" : event.uri().path() })) ?),
        _ 
            => return Ok(response_builder(404, &json!({ "message" : "Path not found" })) ?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

        let client = SecretsManagerClient::new(Region::default());

        // Prepare the request to get the secret value
        let get_secret_value_request = GetSecretValueRequest {
            secret_id: "prod/LavishSecret".to_string(),
            ..Default::default()
        };
    
        let secrete_value: String = match client.get_secret_value(get_secret_value_request).await {
            Ok(response) => {
                let secret_value = match response.secret_string {
                    Some(value) => value,
                    None => {
                        return Err(Error::from("No secret value found"));
                    }
                };
    
                Ok(secret_value)
            }
            Err(e) => Err(Error::from(format!("Failed to read secret: {:?}", e))),
        }?;
    
        let secrete_keys: SecreteKeys = match serde_json::from_str(secrete_value.as_str()) {
            Ok(keys) => keys,
            Err(e) => return Err(Error::from(format!("Failed to deserialize JSON: {:?}", e))),
        };
    
        let refresh_token_private_key = EncodingKey::from_rsa_pem(secrete_keys.jwt_refresh.as_bytes())
            .map_err(|e| Error::from(format!("Failed to create RS256 encoding key: {:?}", e)))?;
        
        let refresh_token_public_key = DecodingKey::from_rsa_pem(secrete_keys.jwt_refresh_pub.as_bytes())
            .map_err(|e| Error::from(format!("Failed to create RS256 encoding key: {:?}", e)))?;
        
        let access_token_private_key = EncodingKey::from_rsa_pem(secrete_keys.jwt_access.as_bytes())
            .map_err(|e| Error::from(format!("Failed to create RS256 encoding key: {:?}", e)))?;
        
        let client_dynamodb = DynamoDbClient::new(Default::default());
        let shared_client_dynamodb = &client_dynamodb;
        
        let func_context: FuncContext = FuncContext { 
            jwt_refresh_key: &refresh_token_private_key, 
            jwt_refresh_pub_key: &refresh_token_public_key, 
            jwt_access_key: &access_token_private_key,
            client_dynamodb: &shared_client_dynamodb
        };
        let shared_func_context = &func_context;


        run(service_fn(move | event: Request | async move {
            function_handler(
                &shared_func_context,
                event
            ).await
        })).await
}
