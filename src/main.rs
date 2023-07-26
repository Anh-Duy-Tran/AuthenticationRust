mod login;
mod model;
mod response_utils;
mod encryptor;
mod register;


use cookie::Cookie;
use encryptor::{TokenError, refresh_access_token, validate_access_token};
use lambda_http::{run, service_fn, Body, Error, Request, Response, http::Method};
use login::{login, GetUserError};
use register::register;
use response_utils::{response_builder_from_string, internal_server_error_builder, CookieAction, response_builder_with_cookies};
use jsonwebtoken::{EncodingKey, DecodingKey};
use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;
use rusoto_secretsmanager::{GetSecretValueRequest, SecretsManager, SecretsManagerClient};

use serde_json::Value;

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
    jwt_access_pub_key: &'a DecodingKey,
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
        Err(_) => return Ok(response_builder_from_string(400, "Invalid request body".to_string())?)
    };

    
    // let (refresh_token, access_token): (Option<String>, Option<String>) = (None, None);
    let (refresh_token, access_token) = match event.headers().get("Cookie") {
        Some(cookies) => {
            let cookies = Cookie::split_parse(cookies.to_str().unwrap().to_string())
            .filter_map(|cookie| cookie.ok());
            
            let mut res_cookie: (Option<String>, Option<String>) = (None, None);
            cookies.for_each(
                |cookie| 
                    if cookie.name() == "refresh_token" {
                        res_cookie.0 = Some(cookie.value().to_string());
                    } else if cookie.name() == "access_token" {
                        res_cookie.1 = Some(cookie.value().to_string());
                    });

            res_cookie
        }
        None => (None, None),
    };

    match (event.method(), event.uri().path()) {
        (&Method::POST, "/main/auth" | "/main/auth/")
            => match refresh_token {
                Some(token) => 
                    match refresh_access_token(token.as_str(), &func_context.jwt_refresh_pub_key, &func_context.jwt_access_key) {
                        Ok(access_token) 
                            => Ok(response_builder_with_cookies(200, "Sign new access_token success".to_string(), None, Some(CookieAction::Set(access_token))) ?),
                        Err(TokenError::InternalServerError(err))
                            => Ok(internal_server_error_builder(err.to_string()) ?),
                        Err(TokenError::TokenValidation(err)) 
                            => Ok(response_builder_with_cookies(403, format!("Token Validation Failed: {}", err), Some(CookieAction::Clear), Some(CookieAction::Clear) ) ?)
                    }
                None => Ok(response_builder_from_string(401, "Missing authentication token, please log-in first.".to_string()) ?)
            }
            
        (&Method::POST, "/main/auth/login" | "/main/auth/login/")
            => match login(&request_json, &func_context.client_dynamodb,&func_context.jwt_access_key, &func_context.jwt_refresh_key).await {
                Ok(res) => Ok(res),
                Err(err) => Ok(internal_server_error_builder(err.to_string())?)
            }

        (&Method::POST, "/main/auth/register" | "/main/auth/register/")
            => match register(&request_json, &func_context.client_dynamodb).await {
                Ok(res) => Ok(res),
                Err(err) => Ok(internal_server_error_builder(err.to_string())?)
            }
            
        (&Method::GET, "/main/auth/user" | "/main/auth/user/")
            => match access_token {
                Some(access_token) 
                    => match validate_access_token(access_token.as_str(), &func_context.jwt_access_pub_key) {
                        Ok(claim) 
                            => match login::get_user(&func_context.client_dynamodb, &claim.email).await {
                                Ok(user) 
                                    => Ok(response_utils::response_builder(200, &serde_json::to_value(&user)?) ?),
                                Err(GetUserError::NotFound)
                                    => Ok(response_builder_with_cookies(404, "Not found, user maybe deleted.".to_string(), None, Some(CookieAction::Clear)) ?),
                                Err(GetUserError::InternalServerError)
                                    => Ok(internal_server_error_builder("Something when wrong when fetching user from db".to_string()) ?),
                            },
                        Err(TokenError::TokenValidation(err))
                            => Ok(response_builder_with_cookies(403, format!("Token Validation Failed: {}", err), None, Some(CookieAction::Clear)) ?),

                        Err(TokenError::InternalServerError(err))
                            => Ok(internal_server_error_builder(err.to_string())?)
                    },
                None 
                    => Ok(response_builder_from_string(401, "Missing authentication token, please log-in first.".to_string()) ?)
            },
        _ 
            => return Ok(response_builder_from_string(404, "Path not found".to_string()) ?)
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

    let access_token_public_key = DecodingKey::from_rsa_pem(secrete_keys.jwt_access_pub.as_bytes())
        .map_err(|e| Error::from(format!("Failed to create RS256 encoding key: {:?}", e)))?;
    
    let client_dynamodb = DynamoDbClient::new(Default::default());
    let shared_client_dynamodb = &client_dynamodb;
    
    let func_context: FuncContext = FuncContext { 
        jwt_refresh_key: &refresh_token_private_key, 
        jwt_refresh_pub_key: &refresh_token_public_key, 
        jwt_access_key: &access_token_private_key,
        jwt_access_pub_key: &access_token_public_key,
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
