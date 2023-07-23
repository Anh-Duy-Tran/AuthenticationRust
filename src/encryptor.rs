use argon2::{self, Config};
use chrono::{Duration, Utc};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::{encode, Header, Algorithm};
use rand::{self, RngCore};
use crate::model::Claims;
use crate::model::User;

pub fn verify_password(hashed_password: &str, user_password: &str) -> bool {
    match argon2::verify_encoded(hashed_password, user_password.as_bytes()) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn hash_password(password: &str) -> Result<String, argon2::Error> {
    // Generate random salt for each password
    let salt = generate_salt();
    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt , &config).unwrap();
    Ok(hash)
}

fn create_claim(email: &String, role: &String, exp_duration: Duration) -> Claims {
    Claims { email : email.clone(), role : role.clone(), iat: Utc::now().timestamp(), exp: (Utc::now() + exp_duration).timestamp() }
}

pub fn sign_new_tokens(
    user: &User, 
    access_token_private_key: &EncodingKey, 
    refresh_token_private_key: &EncodingKey
) -> Result<(String, String), crate::Error> {
    let access_token = encode(&Header::new(Algorithm::RS256), &create_claim(&user.email, &user.role.to_string(), Duration::seconds(5)), &access_token_private_key)?;
    let refresh_token = encode(&Header::new(Algorithm::RS256), &create_claim(&user.email, &user.role.to_string(), Duration::seconds(10)), &refresh_token_private_key)?;
  
    return Ok((refresh_token, access_token));
}

