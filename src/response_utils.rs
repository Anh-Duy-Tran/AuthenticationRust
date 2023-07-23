use lambda_http::{Response, Body, Error, http::header::HeaderValue};
use serde_json::{Value, json};

pub fn response_builder_from_string(status_code: u16, payload : String) -> Result<Response<Body>, Error> {
    Response::builder()
    .header("content-type", "application/json")
    .status(status_code)
    .body(Body::Text(serde_json::to_string(&json!({
        "message" : payload,
        "status" : if status_code < 300 {"Success"} else {"Failed"}
    }))?))
    .map_err(|err| Error::from(err))
}

pub fn response_builder(status_code: u16, payload : &Value) -> Result<Response<Body>, Error> {
    Response::builder()
    .header("content-type", "application/json")
    .status(status_code)
    .body(Body::Text(serde_json::to_string(payload)?))
    .map_err(|err| Error::from(err))
}

pub fn response_builder_with_cookies(
    status_code: u16, 
    payload : &Value, 
    refresh_token: Option<String>, 
    access_token: Option<String>
) -> Result<Response<Body>, Error> {
    
    Response::builder()
        .header("content-type", "application/json")
        .status(status_code)
        .header("set-cookie", refresh_token.unwrap_or_default().clone())
        .header("set-cookie", access_token.unwrap_or_default().clone())
        .body(Body::Text(serde_json::to_string(payload)?))
        .map_err(|err| Error::from(err))
}
pub fn internal_server_error_builder(message: String) -> Result<Response<Body>, Error> {
    Response::builder()
    .header("content-type", "application/json")
    .status(500)
    .body(Body::Text(serde_json::to_string( &json!({
        "Internal Server Error" : message
    }) )? ))
    .map_err(|err| Error::from(err))
}