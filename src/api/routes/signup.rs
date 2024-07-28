use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use surrealdb::{engine::remote::ws::Client, Surreal};
use totp_rs::{Algorithm, Secret, TOTP};
use serde::Deserialize;
use rand::Rng;
use base32;
use reqwest::Client;
use std::env;
use chrono::{Duration, Utc};
use lettre::message::{header, SinglePart};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

use crate::{app_error::AppError, db::models::user::{User, GenericResponse, TemporaryUser}};


#[derive(Deserialize, Debug)]
pub struct UserCreationBody {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    pub email_id: String,
    pub country: String,
}

#[derive(Deserialize)]
pub struct VerifyOTPSchema {
    pub email_id: String,
    pub otp: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateOTPSchema {
    pub email: String,
    pub user_id: String,
}

pub async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "Implementing signup functionality in rust";

    HttpResponse::Ok().json(json!({"status": "success", "message": MESSAGE}))
}

pub async fn send_email_smtp(to: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from("xps.universe@gmail.com".parse()?)
        .reply_to("xps.universe@gmail.com".parse()?)
        .to(to.parse()?)
        .subject("Verify your Email Address")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(format!("This is your one-time-password (OTP) code: {}", otp)),
        )?;

    let creds = Credentials::new("xps.universe@gmail.com".to_string(), "ngmr halg tdss ynwe".to_string());

    let mailer = SmtpTransport::relay("smtp.example.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

pub async fn register(
    body: web::Json<UserCreationBody>,
    db: web::Data<Surreal<Client>>,
) -> Result<HttpResponse, AppError> {
    let username = body.username.clone();
    let first_name = body.first_name.clone();
    let last_name = body.last_name.clone();
    let password = body.password.clone();

    let email_id = body.email_id.clone();
    let country = body.country.clone();

        // Generate OTP
        let mut rng = rand::thread_rng();
        let data_byte: [u8; 21] = rng.gen();
        let base32_string = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &data_byte);
    
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(base32_string.clone()).to_bytes().unwrap(),
        ).unwrap();
    
        let otp_base32 = totp.get_secret_base32();
        let otp_timestamp = Utc::now();
    
        // Store temporary user with OTP
        let temp_user = TemporaryUser {
            username,
            first_name,
            last_name,
            password,
            email_id: email_id.clone(),
            country,
            otp_enabled: None,
            otp_verified: None,
            otp_base32: otp_base32.clone(),
            otp_auth_url: None,
            otp_timestamp,
        };
    
        // Save to temporary storage (in-memory or separate DB table)
    // Save to temporary storage (in-memory or separate DB table)
    let query = "INSERT INTO temporary_users (username, first_name, last_name, password, email_id, country, otp_enabled, otp_verified, otp_base32, otp_auth_url) 
                 VALUES ($username, $first_name, $last_name, $password, $email_id, $country, $otp_enabled, $otp_verified, $otp_base32, $otp_auth_url)";
    db.query(query)
        .bind("username", &temp_user.username)
        .bind("first_name", &temp_user.first_name)
        .bind("last_name", &temp_user.last_name)
        .bind("password", &temp_user.password)
        .bind("email_id", &temp_user.email_id)
        .bind("country", &temp_user.country)
        .bind("otp_enabled", &temp_user.otp_enabled)
        .bind("otp_verified", &temp_user.otp_verified)
        .bind("otp_base32", &temp_user.otp_base32)
        .bind("otp_auth_url", &temp_user.otp_auth_url)
        .await
        .unwrap();
    
        // Send OTP to user via email
        send_email_smtp(&email_id, &otp_base32);
    
        HttpResponse::Ok().json(json!({"message": "OTP sent to your email"}))

    // let mut new_user: User = User {
    //     id: None,
    //     username,
    //     first_name,
    //     last_name,
    //     email_id,
    //     password,
    //     country,
    //     avatar: None,
    //     is_admin: false,
    //     otp_enabled: Some(false),
    //     otp_verified: Some(false),
    //     otp_base32: None,
    //     otp_auth_url: None,
    //     created_at: chrono::Utc::now().into(),
    // };

    // if otp_enabled is false, the user creation should fail

    // Hashing of password id done internally in the create function after user existing check
    // let new_user = new_user.create(&db).await?;

    // match new_user {
    //     Some(user) => {
    //         let response_body = json!({
    //             "status": 201,
    //             "message": "User Created",
    //             "user": user,
    //         });
    //         Ok(HttpResponse::Created().json(response_body))
    //     }
    //     None => Ok(HttpResponse::Ok().finish()),
    // }
}

pub async fn verify_otp(
    body: web::Json<VerifyOTPSchema>,
    db: web::Data<Surreal<Client>>,
) -> impl Responder {
    let email_id = body.email_id.clone();
    let otp = body.otp.clone();

    // Retrieve temporary user
    let temp_user: Option<TemporaryUser> = db
        .query("SELECT * FROM temporary_users WHERE email_id = $email_id")
        .bind("email_id", &email_id)
        .await.unwrap()
        .take(0)?;

    if let Some(user) = temp_user {
        let otp_timestamp = user.otp_timestamp;

        // Check if the OTP is expired
        if Utc::now().signed_duration_since(otp_timestamp) > Duration::minutes(10) {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: "OTP is expired".to_string(),
            };

            return HttpResponse::Forbidden().json(json_error);
        }

        // Validate OTP
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(user.otp_base32.clone()).to_bytes().unwrap(),
        ).unwrap();

        let is_valid = totp.check_current(&otp).unwrap();

        if is_valid {
            // Move user from temporary storage to main user table
            let new_user = User {
                id: None,
                username: user.username,
                first_name: user.first_name,
                last_name: user.last_name,
                email_id: user.email_id,
                password: user.password,
                country: user.country,
                avatar: None,
                is_admin: false,
                otp_enabled: Some(true),
                otp_verified: Some(true),
                otp_base32: Some(user.otp_base32),
                otp_auth_url: None,
                created_at: chrono::Utc::now().into(),
            };

            new_user.create(&db).await?;

            // Delete temporary user
            db.query("DELETE FROM temporary_users WHERE email_id = $email_id")
                .bind("email_id", &email_id)
                .await.unwrap();

            return HttpResponse::Ok().json(json!({"message": "User registered successfully"}));
        } else {
            return HttpResponse::Forbidden().json(json!({"message": "Invalid OTP"}));
        }
    }

    HttpResponse::NotFound().json(json!({"message": "User not found"}))
}



pub async fn validate_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    db: web::Data<Surreal<Client>>,
) -> impl Responder {
    let user_id = body.user_id.clone();

    // Fetch user from the database
    let user: Option<User> = db
        .query("SELECT * FROM user WHERE id = $user_id")
        .bind("user_id", &user_id)
        .await
        .map_err(|e| {
            let json_error = GenericResponse {
                status: "fail".to_string(),
                message: format!("Error querying user: {}", e),
            };
            HttpResponse::InternalServerError().json(json_error)
        })?
        .take(0)?;

    if user.is_none() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: format!("No user with Id: {} found", body.user_id),
        };
        return HttpResponse::NotFound().json(json_error);
    }

    let user = user.unwrap();

    if !user.otp_enabled.unwrap() {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };
        return HttpResponse::Forbidden().json(json_error);
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
    )
    .unwrap();

    let is_valid = totp.check_current(&body.token).unwrap();

    if !is_valid {
        return HttpResponse::Forbidden()
            .json(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"}));
    }

    HttpResponse::Ok().json(json!({"otp_valid": true}))
}
