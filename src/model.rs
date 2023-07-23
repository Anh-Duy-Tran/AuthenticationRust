use std::fmt;

use serde::{Serialize, Deserialize};

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum Role {
    Customer,
    Admin,
    NoRole
}

impl Role {
    pub fn from_str(role: &str) -> Role {
        match role {
            "Admin" => Role::Admin,
            "Customer" => Role::Customer,
            _ => Role::NoRole
        }
  }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "Admin"),
            Role::Customer => write!(f, "Customer"),
            Role::NoRole => write!(f, "Unknown")
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub hashed_password: String,
    pub role: Role
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserDTO {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub email: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64
}