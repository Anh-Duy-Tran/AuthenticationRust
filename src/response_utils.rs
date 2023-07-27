use cookie::{Cookie, time::{Duration, OffsetDateTime}};
use lambda_http::{Response, Body, Error};
use serde_json::{Value, json};

const DOMAIN: &str = "lavish-duytran.com";

pub fn response_builder_from_string(status_code: u16, payload : String) -> Result<Response<Body>, Error> {
    Response::builder()
    .header("content-type", "application/json")
    .header("Access-Control-Allow-Origin", "*")
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
    .header("Access-Control-Allow-Origin", "*")
    .status(status_code)
    .body(Body::Text(serde_json::to_string(payload)?))
    .map_err(|err| Error::from(err))
}

fn build_cookie(name: &str, value: String) -> String {
    Cookie::build(name, value)
        .domain(DOMAIN)
        .path("/auth")
        .secure(true)
        .http_only(true)
        .max_age(Duration::minutes(2))
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

pub enum CookieAction {
    Set(String),
    Clear
}

pub fn response_builder_with_cookies(
    status_code: u16, 
    payload : String, 
    refresh_token: Option<CookieAction>, 
    access_token: Option<CookieAction>
) -> Result<Response<Body>, Error> {

    let refresh_cookie = match refresh_token {
        Some(CookieAction::Set(token)) => build_cookie("refresh_token", token),
        Some(CookieAction::Clear) => build_expired_cookie("refresh_token"),
        None => "".to_string()
    };
    let access_cookie = match access_token {
        Some(CookieAction::Set(token)) => build_cookie("access_token", token),
        Some(CookieAction::Clear) => build_expired_cookie("access_token"),
        None => "".to_string()
    };
    
    Response::builder()
        .header("content-type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .status(status_code)
        .header("set-cookie", refresh_cookie)
        .header("set-cookie", access_cookie)
        .body(Body::Text(serde_json::to_string(&json!({
            "message" : payload,
            "status" : if status_code < 300 {"Success"} else {"Failed"}
        }))?))
        .map_err(|err| Error::from(err))
}
pub fn internal_server_error_builder(message: String) -> Result<Response<Body>, Error> {
    Response::builder()
    .header("content-type", "application/json")
    .header("Access-Control-Allow-Origin", "*")
    .status(500)
    .body(Body::Text(serde_json::to_string( &json!({
        "Internal Server Error" : message
    }) )? ))
    .map_err(|err| Error::from(err))
}