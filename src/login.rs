use cookie::Cookie;
use cookie::time::{Duration, OffsetDateTime};
use jsonwebtoken::EncodingKey;
use lambda_http::{Response, Body, Error};
use rusoto_dynamodb::{DynamoDbClient, GetItemInput, AttributeValue, DynamoDb};
use serde_json::{Value, json};
use crate::model::{User, Role};

use crate::response_utils::{response_builder_with_cookies, response_builder_from_string, internal_server_error_builder};
use crate::encryptor::{verify_password, sign_new_tokens};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum GetUserError {
    NotFound,
    InternalServerError,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct LoginPayload {
    email: String,
    password: String,
}

const DOMAIN: &str = "lavish-duytran.com";

async fn get_user(client: &DynamoDbClient, email : &str) -> Result<User, GetUserError> {
    let mut get_item_input = GetItemInput::default();

    get_item_input.table_name = "UserTable-Lavish".to_string();
    get_item_input.key = {
        let mut attribute_map = std::collections::HashMap::new();
        attribute_map.insert("email".to_string(), AttributeValue {
            s: Some(email.to_string()),
            ..Default::default()
        });
        attribute_map
    };

    // Call the DynamoDB get_item method
    let result = match client.get_item(get_item_input).await {
        Ok(res) => res,
        Err(_) => return Err(GetUserError::InternalServerError)
    };

    let item = result.item.ok_or(GetUserError::NotFound)?;

    let user_details : User = {
        let get_string_field = |field: &str| -> Option<String> {
            item.get(field)?.s.clone()
        };

        let first_name = get_string_field("first_name").ok_or(GetUserError::InternalServerError)?;
        let role = get_string_field("role").ok_or(GetUserError::InternalServerError)?;
        let last_name = get_string_field("last_name").ok_or(GetUserError::InternalServerError)?;
        let hashed_password = get_string_field("hashed_password").ok_or(GetUserError::InternalServerError)?;

        User {
            email : email.to_string(),
            first_name,
            last_name,
            role : Role::from_str(role.as_str()),
            hashed_password
        }
    };

    Ok(user_details)
}

fn build_cookie(name: &str, value: &str) -> String {
    Cookie::build(name, value)
        .domain(DOMAIN)
        .path("/auth")
        .secure(true)
        .http_only(true)
        .max_age(Duration::seconds(10))
        .finish()
        .to_string()
}

fn build_expired_cookie(name: &str) -> String {
    Cookie::build(name, "")
    .domain(DOMAIN)
    .path("/auth")
    .secure(true)
    .http_only(true)
    .max_age(Duration::seconds(0))
    .expires(OffsetDateTime::now_utc())
    .finish()
    .to_string()
}

pub async fn login(request : &Value, client_dynamodb: &DynamoDbClient, access_token_private_key: &EncodingKey, refresh_token_private_key: &EncodingKey) -> Result<Response<Body>, Error> {
    let payload: LoginPayload = match serde_json::from_value(request.to_owned()) {
        Ok(data) => data,
        Err(err) => {
            return Ok(response_builder_from_string(400, format!("Bad request: {}", err)) ?)
        }
    };

    let email = payload.email;
    let password = payload.password;

    let user : User = match get_user(client_dynamodb, &email).await {
        Ok(user) => user,
        Err(GetUserError::NotFound) => {
            return Ok(response_builder_from_string(401, "Login Failed: Incorrect Email or Password.".to_string())?);
        }
        Err(GetUserError::InternalServerError) => {
            return Ok(response_builder_from_string(500, "Login Failed: Missing or Invalid User Information in the Database.".to_string())?);
        }
    };
    
    if verify_password(&user.hashed_password, &password) {
        let (refresh_token, access_token) = match sign_new_tokens(&user, &access_token_private_key, &refresh_token_private_key) {
            Ok(payload) => payload,
            Err(err) => return Ok(internal_server_error_builder(err.to_string())?)
        };

        let access_token_cookie = build_cookie("access_token", access_token.as_str());
        let refress_token_cookie = build_cookie("refresh_token", refresh_token.as_str());
        
        return Ok(response_builder_with_cookies(200, &json!({
            "message" : format!("Log-in success, Welcome {}", user.first_name)
        }), Some(access_token_cookie), Some(refress_token_cookie)) ?)
    } else {
        return Ok(response_builder_from_string(401, "Login Failed: Incorrect Email or Password.".to_string())?);
    }
}