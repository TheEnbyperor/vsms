#[macro_use]
extern crate serde;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use std::env;
use dotenv::dotenv;
use std::io::Read;
use futures::compat::Future01CompatExt;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, middleware, web};

mod sanitizer;

#[derive(Clone)]
pub struct AppState {
    oauth: rust_keycloak::oauth::OAuthClient,
    api_key: ApiKey,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    agent_id: String
}

fn oauth_client() -> rust_keycloak::oauth::OAuthClient {
    dotenv().ok();

    let client_id = env::var("CLIENT_ID")
        .expect("CLIENT_ID must be set");
    let client_secret = env::var("CLIENT_SECRET")
        .expect("CLIENT_SECRET must be set");
    let well_known_url = env::var("OAUTH_WELL_KNOWN")
        .unwrap_or("https://account.cardifftec.uk/auth/realms/wwfypc-dev/.well-known/openid-configuration".to_string());

    let config = rust_keycloak::oauth::OAuthClientConfig::new(&client_id, &client_secret, &well_known_url).unwrap();

    rust_keycloak::oauth::OAuthClient::new(config)
}

fn agent_id() -> String {
    dotenv().ok();

    let agent_id = env::var("AGENT_ID")
        .expect("AGENT_ID must be set");

    agent_id
}

fn get_keys() -> openssl::pkey::PKey<openssl::pkey::Private> {
    dotenv().ok();

    let key_file = env::var("PRIVATE_KEY")
        .unwrap_or("private.pem".to_string());
    let mut buf = Vec::new();
    let mut file = std::fs::File::open(key_file).unwrap();
    file.read_to_end(&mut buf).expect("Unable to read private key");
    let key = openssl::pkey::PKey::private_key_from_pem(&buf)
        .expect("Certificate isn't a valid PEM private key");
    key
}
struct ApiKeyInt {
    token: String,
    expires_at: u64,
    key: openssl::rsa::Rsa<openssl::pkey::Private>,
    email: String,
}
#[derive(Clone)]
struct ApiKey(std::sync::Arc<std::sync::RwLock<ApiKeyInt>>);

impl ApiKey {
    fn key(&self) -> String {
        let int = self.0.read().unwrap();
        let start = std::time::SystemTime::now();
        let since_the_epoch = start.duration_since(std::time::UNIX_EPOCH).expect("Time went backwards").as_secs();
        if since_the_epoch >= int.expires_at {
            std::mem::drop(int);
            let mut int = self.0.write().unwrap();
            info!("Getting google access token...");

            let jwt = encode_jwt_rsa(&JWTHeader {
                alg: "RS256".to_string()
            }, &ServiceAccountClaims {
                iss: int.email.clone(),
                scope: "https://www.googleapis.com/auth/verifiedsms".to_string(),
                aud: "https://www.googleapis.com/oauth2/v4/token".to_string(),
                exp: since_the_epoch,
                iat: since_the_epoch
            }, &int.key).expect("Unable to generate JWT");

            let client = reqwest::Client::new();
            let res: ServiceAccountResponse = client.post("https://www.googleapis.com/oauth2/v4/token").json(&ServiceAccountRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
                assertion: jwt
            }).send().expect("Unable to contact google").json().expect("Invalid JSON received");

            info!("Got google access token");

            int.token = res.access_token;
            int.expires_at = since_the_epoch + res.expires_in;
            return int.token.clone();
        }
        int.token.clone()
    }
}

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String
}
#[derive(Serialize)]
struct ServiceAccountClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}
#[derive(Serialize)]
struct ServiceAccountRequest {
    grant_type: String,
    assertion: String
}
#[derive(Deserialize)]
struct ServiceAccountResponse {
    access_token: String,
    expires_in: u64
}

fn get_access_token() -> ApiKey {
    dotenv().ok();

    let key_file = env::var("SERVICE_ACCOUNT_KEY")
        .unwrap_or("service-account.json".to_string());
    let file = std::fs::File::open(key_file).unwrap();
    let a: ServiceAccount = serde_json::from_reader(file).unwrap();

    let key = openssl::pkey::PKey::private_key_from_pem(a.private_key.as_bytes())
        .expect("Certificate isn't a valid PEM private key");
    let key = key.rsa().expect("Certificate isn't a RSA key");

    ApiKey(std::sync::Arc::new(std::sync::RwLock::new(ApiKeyInt {
        token: "".to_string(),
        expires_at: 0,
        key,
        email: a.client_email
    })))
}

#[derive(Debug, Serialize, Deserialize)]
struct JWTHeader {
    alg: String,
}

fn encode_jwt_rsa<H: serde::Serialize, C: serde::Serialize>(header: &H, claims: &C, priv_key: &openssl::rsa::RsaRef<openssl::pkey::Private>) -> failure::Fallible<String> {
    let header_str = base64::encode_config(&serde_json::to_string(header)?, base64::URL_SAFE_NO_PAD);
    let claims_str = base64::encode_config(&serde_json::to_string(claims)?, base64::URL_SAFE_NO_PAD);

    let mut secret = String::new();
    secret.push_str(&header_str);
    secret.push('.');
    secret.push_str(&claims_str);

    let pkey = openssl::pkey::PKey::from_rsa(priv_key.to_owned())?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)?;
    signer.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
    signer.update(&secret.as_bytes())?;
    let signature = base64::encode_config(&signer.sign_to_vec()?, base64::URL_SAFE_NO_PAD);

    secret.push('.');
    secret.push_str(&signature);

    Ok(secret)
}

#[derive(Clone, Debug, Deserialize)]
struct MessageData {
    to: String,
    contents: String
}

#[derive(Serialize)]
struct UserKeyRequest {
    #[serde(rename = "phoneNumbers")]
    phone_numbers: Vec<String>
}
#[derive(Deserialize, Debug)]
struct UserKey {
    #[serde(rename = "phoneNumber")]
    phone_number: String,
    #[serde(rename = "publicKey")]
    public_key: String
}
#[derive(Deserialize, Debug)]
struct UserKeyResponse {
    #[serde(rename = "userKeys")]
    user_keys: Vec<UserKey>
}

#[derive(Serialize)]
struct StoreHashesHashes {
    values: Vec<String>,
    #[serde(rename = "rateLimitTokens")]
    rate_limit_tokens: Vec<String>
}
#[derive(Serialize)]
struct StoreHashesRequest {
    hashes: StoreHashesHashes,
    #[serde(rename = "publicKey")]
    public_key: String,
}

async fn send_message(token: rust_keycloak::oauth::BearerAuthToken, data: web::Data<AppState>, message: web::Json<MessageData>) -> actix_web::Result<impl actix_web::Responder> {
    data.oauth.verify_token(token.token(), "send-messages").await?;

    let number = phonenumber::parse(Some(phonenumber::country::GB), &message.to)?;
    if !phonenumber::is_valid(&number) {
        return Ok(
            HttpResponse::BadRequest()
                .body("Invalid phone number")
        );
    }
    let number_str = phonenumber::format(&number).mode(phonenumber::Mode::E164).to_string();

    let client = reqwest::r#async::Client::new();
    let mut req = rust_keycloak::util::async_reqwest_to_error(client.post("https://verifiedsms.googleapis.com/v1/userKeys:batchGet")
        .json(&UserKeyRequest {
            phone_numbers: vec![number_str.clone()]
        })
        .bearer_auth(&data.api_key.key())).await?;
    let keys: UserKeyResponse = match req.json().compat().await {
        Ok(k) => k,
        Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
    };

    match keys.user_keys.into_iter().find(|k| k.phone_number == number_str) {
        Some(user_key) => {
            let pub_key = match base64::decode(&user_key.public_key) {
                Ok(k) => k,
                Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
            };

            let key = match openssl::pkey::PKey::public_key_from_der(&pub_key) {
                Ok(k) => k,
                Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
            };
            let mut dh = match openssl::derive::Deriver::new(&data.private_key) {
                Ok(k) => k,
                Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
            };
            match dh.set_peer(&key) {
                Ok(_) => {},
                Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
            };
            let shared_secret = match dh.derive_to_vec() {
                Ok(k) => k,
                Err(e) => return Ok(HttpResponse::InternalServerError().body(e.to_string()))
            };

            let make_hash = |msg: &str| -> String {
                let h = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret);
                let mut msg_hash = [0u8; 32];
                h.expand(msg.as_bytes(), &mut msg_hash).unwrap();
                base64::encode_config(&msg_hash, base64::URL_SAFE)
            };
            let mut hashes = vec![make_hash(&message.contents)];
            let sanitized_msg = sanitizer::sanitize_string(&message.contents);
            if sanitized_msg != message.contents {
                hashes.push(make_hash(&sanitized_msg))
            }

            let h = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret);
            let mut rate_limit_token = [0u8; 32];
            h.expand("xELpwbCabRriJEkOYBagfJpHrrmNqlaZMTxsacBQjsLjUHtQexWNQCiMCkrxBzWEifExJkkOJwOziTQQJyRWVUbauuCHZrYlenSAiqtKtT".as_bytes(), &mut rate_limit_token).unwrap();
            let rate_limit_token = base64::encode_config(&rate_limit_token, base64::URL_SAFE);

            let mut req = rust_keycloak::util::async_reqwest_to_error(client.post(&format!("https://verifiedsms.googleapis.com/v1/agents/{}:storeHashes", &data.agent_id))
                .json(&StoreHashesRequest {
                    hashes: StoreHashesHashes {
                        values: hashes,
                        rate_limit_tokens: vec![rate_limit_token]
                    },
                    public_key: base64::encode_config(&data.private_key.public_key_to_der().unwrap(), base64::URL_SAFE)
                })
                .bearer_auth(&data.api_key.key())).await?;
            println!("{:?}", req.text().compat().await);
        },
        None => {}
    }

    Ok(
        HttpResponse::Ok()
            .finish()
    )
}

#[derive(Serialize, Deserialize)]
struct GoogleKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: String,
}

fn check_key(api_key: &ApiKey, private_key: &openssl::pkey::PKey<openssl::pkey::Private>, agent_id: &str) {
    info!("Checking public key...");
    let cur_key = base64::encode(&private_key.public_key_to_der().unwrap());
    let client = reqwest::Client::new();
    let mut res = client.get(&format!("https://verifiedsms.googleapis.com/v1/agents/{}/key/", agent_id))
        .bearer_auth(&api_key.key()).send().unwrap();
    if res.status() != reqwest::StatusCode::NOT_FOUND {
        let key: GoogleKey = res.json().unwrap();
        if key.public_key == cur_key {
            info!("Key already up to date");
            return;
        }
    }
    client.patch(&format!("https://verifiedsms.googleapis.com/v1/agents/{}/key/", agent_id))
        .bearer_auth(&api_key.key())
        .json(&GoogleKey {
            name: None,
            public_key: cur_key
        }).send().unwrap();
    info!("Key updated");
}

fn main() {
    pretty_env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();

    let api_key = get_access_token();
    let private_key = get_keys();
    let agent_id = agent_id();

    check_key(&api_key, &private_key, &agent_id);

    let data = AppState {
        oauth: oauth_client(),
        api_key,
        private_key,
        agent_id
    };

    let sys = actix::System::new("vsms");
    let mut server = HttpServer::new(move || {
        App::new()
            .data(data.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route("/message/new/", web::post().to_async(actix_web_async_await::compat3(send_message)))
    });

    let mut listenfd = listenfd::ListenFd::from_env();

    info!("Start listening...");
    server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        server.listen(l).unwrap()
    } else {
        server.bind("127.0.0.1:3000").unwrap()
    };

    server.start();
    let _ = sys.run();
}