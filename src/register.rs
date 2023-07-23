use chrono::Utc;
use lambda_http::{Response, Body, Error};
use rusoto_dynamodb::{DynamoDbClient, GetItemInput, AttributeValue, DynamoDb, PutItemInput};
use serde_json::{Value, json};
use crate::model::{Role, UserDTO};
use crate::encryptor::hash_password;
use crate::response_utils::{response_builder, internal_server_error_builder, response_builder_from_string};

pub async fn register(request: &Value, client_dynamodb: &DynamoDbClient) -> Result<Response<Body>, Error> {
    let payload: UserDTO = match serde_json::from_value(request.to_owned()) {
        Ok(payload) => payload,
        Err(err) => return Ok(response_builder_from_string( 400, err.to_string() )?),
    };

    // Check if the user already exists in the database
    let get_item_input = GetItemInput {
        table_name: "UserTable-Lavish".to_string(),
        key: {
            let mut key = std::collections::HashMap::new();
            key.insert("email".to_string(), AttributeValue { s: Some(payload.email.clone()), ..Default::default() });
            key
        },
        ..Default::default()
    };

    match client_dynamodb.get_item(get_item_input).await {
        Ok(output) => {
            if output.item.is_some() {
                return Ok(response_builder(400, &json!({
                    "message": "Email already exists.".to_string(),
                    "status": "Failed".to_string(),
                })) ?)
            }
        }
        Err(err) => return Ok(internal_server_error_builder(err.to_string())?)
    }

    let input = PutItemInput {
        table_name: "UserTable-Lavish".to_string(),
        item: {
            let mut item = std::collections::HashMap::new();
            item.insert("creation_timestamp".to_string(), AttributeValue { n: Some(Utc::now().timestamp().to_string()), ..Default::default() });
            item.insert("email".to_string(), AttributeValue { s: Some(payload.email), ..Default::default() });
            item.insert("first_name".to_string(), AttributeValue { s: Some(payload.first_name), ..Default::default() });
            item.insert("last_name".to_string(), AttributeValue { s: Some(payload.last_name), ..Default::default() });
            item.insert("role".to_string(), AttributeValue { s: Some(Role::Customer.to_string()), ..Default::default() });
            item.insert("hashed_password".to_string(), AttributeValue { s: Some(hash_password(&payload.password)?), ..Default::default()});
            item.insert("password_hash_timestamp".to_string(), AttributeValue { n: Some(Utc::now().timestamp().to_string()), ..Default::default() });
            item
        },
        ..Default::default()
    };

    match client_dynamodb.put_item(input).await {
        Ok(_) => {
            let res = json!({
                "message" : "New Account Created, please use your credentials in /auth/login!".to_string(),
                "status": "Success".to_string()
            });
            return Ok(response_builder(201, &res)?)

        }
        Err(err) => return Ok(internal_server_error_builder(err.to_string())?)
    }
}