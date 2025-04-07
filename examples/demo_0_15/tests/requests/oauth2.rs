use std::env;

use crate::requests::prepare_data;
use demo_0_15::views::auth::CurrentResponse;
use demo_0_15::{app::App, models::users::OAuth2UserProfile, views::auth::LoginResponse};
use loco_rs::testing::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serial_test::serial;
use url::Url;
use wiremock::{
    matchers::{basic_auth, bearer_token, body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Deserialize, Serialize, Clone, Debug)]
struct ExchangeMockBody {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
}

struct OAuth2Settings {
    client_id: String,
    client_secret: String,
    code: String,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    profile_url: String,
    protected_url: String,
    scope: String,
    exchange_mock_body: ExchangeMockBody,
    profile_mock_body: OAuth2UserProfile,
    mock_server: MockServer,
}

impl OAuth2Settings {
    async fn new() -> Self {
        // Request a new server from the pool
        let server = MockServer::start().await;
        // Use one of these addresses to configure your client
        let url = server.uri();
        let exchange_mock_body = ExchangeMockBody {
            access_token: "test_access_token".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 3600,
            refresh_token: "test_refresh_token".to_string(),
        };
        let user_profile = OAuth2UserProfile {
            email: "test_email@gmail.com".to_string(),
            name: "test_name".to_string(),
            picture: Some("test_picture".to_string()),
            sub: "test_sub".to_string(),
            email_verified: true,
            family_name: Some("test_family_name".to_string()),
            given_name: Some("test_given_name".to_string()),
            locale: Some("test_locale".to_string()),
        };
        Self {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            code: "test_code".to_string(),
            auth_url: format!("{url}/auth_url",),
            token_url: format!("{url}/token_url",),
            redirect_url: format!("{url}/redirect_url",),
            profile_url: format!("{url}/profile_url",),
            protected_url: format!("{url}/oauth/protected_url",),
            scope: format!("{url}/scope_1",),
            exchange_mock_body,
            profile_mock_body: user_profile,
            mock_server: server,
        }
    }
}

async unsafe fn set_default_url() -> OAuth2Settings {
    let settings = OAuth2Settings::new().await;
    let vars = vec![
        // OAUTH_CLIENT_ID
        ("OAUTH_CLIENT_ID", &settings.client_id),
        // OAUTH_CLIENT_SECRET
        ("OAUTH_CLIENT_SECRET", &settings.client_secret),
        // AUTH_URL
        ("AUTH_URL", &settings.auth_url),
        // TOKEN_URL
        ("TOKEN_URL", &settings.token_url),
        // REDIRECT_URL
        ("REDIRECT_URL", &settings.redirect_url),
        // PROFILE_URL
        ("PROFILE_URL", &settings.profile_url),
        // SCOPE_1
        ("SCOPES_1", &settings.scope),
        // SCOPE_2
        ("SCOPES_2", &settings.scope),
        // PROTECTED_URL
        ("PROTECTED_URL", &settings.protected_url),
    ];
    for (key, value) in vars {
        env::set_var(key, value);
    }
    settings
}
async fn mock_oauth_server(
    settings: &OAuth2Settings,
    expect_success: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_calls = u64::from(expect_success);
    let token_form_body = vec![
        serde_urlencoded::to_string([("code", &settings.code)])?,
        serde_urlencoded::to_string([("redirect_uri", &settings.redirect_url)])?,
        serde_urlencoded::to_string([("grant_type", "authorization_code")])?,
    ];
    // Create a mock for the token exchange - https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/
    let mut token_mock = Mock::given(method("POST"))
        .and(path("/token_url"))
        // Client Authorization Auth Header from RFC6749(OAuth2) - https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
        .and(basic_auth(
            settings.client_id.clone(),
            settings.client_secret.clone(),
        ));
    // Access Token Request Body from RFC6749(OAuth2) - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    for url in token_form_body {
        token_mock = token_mock.and(body_string_contains(url));
    }
    token_mock
        .respond_with(ResponseTemplate::new(200).set_body_json(settings.exchange_mock_body.clone()))
        .expect(expected_calls)
        .mount(&settings.mock_server)
        .await;
    // Create a mock for getting profile - https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    Mock::given(method("GET"))
        .and(path("/profile_url"))
        .and(bearer_token(
            settings.exchange_mock_body.access_token.clone(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(settings.profile_mock_body.clone()))
        .expect(expected_calls)
        .mount(&settings.mock_server)
        .await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_settings() {
    let settings = unsafe { set_default_url() }.await;
    assert_eq!(settings.auth_url, env::var("AUTH_URL").unwrap());
    assert_eq!(settings.token_url, env::var("TOKEN_URL").unwrap());
    assert_eq!(settings.redirect_url, env::var("REDIRECT_URL").unwrap());
    assert_eq!(settings.profile_url, env::var("PROFILE_URL").unwrap());
    assert_eq!(settings.scope, env::var("SCOPES_1").unwrap());
    assert_eq!(settings.scope, env::var("SCOPES_2").unwrap());
    assert_eq!(settings.protected_url, env::var("PROTECTED_URL").unwrap());
}

#[tokio::test]
#[serial]
async fn can_google_authorization_url() -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    let assert_html = vec![
        settings.auth_url.clone(),
        serde_urlencoded::to_string([("response_type", "code")])?,
        serde_urlencoded::to_string([("client_id", &settings.client_id)])?,
        serde_urlencoded::to_string([("redirect_uri", &settings.redirect_url)])?,
        serde_urlencoded::to_string([("scope", &settings.scope)])?,
    ];

    request::<App, _, _>(|request, _ctx| async move {
        // Test the authorization url
        let res = request.get("/api/oauth2/google").await;
        assert_eq!(res.status_code(), 200);
        for url in assert_html {
            assert!(res.text().contains(&url));
        }
    })
    .await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn can_call_google_callback_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // mock oauth2 server
    mock_oauth_server(&settings, true).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Get the authorization url from the server
        let auth_res = request.get("/api/oauth2/google").await;
        // Cookie for csrf token
        let auth_cookie = auth_res.cookies();
        // Get the authorization url from the response HTML
        let mut auth_url = String::new();
        let re = Regex::new(r#"([^"]*)"#).unwrap();
        for cap in re.captures_iter(&auth_res.text()) {
            auth_url = cap[1].to_string();
        }
        // Extract the state from the auth_url
        let state = Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());
        // Test the google callback with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/cookie")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.unwrap()),
            ])
            .add_cookies(auth_cookie)
            .await;
        assert_eq!(res.status_code(), 303);
        assert_eq!(
            res.headers().get("location").unwrap(),
            &settings.protected_url
        );
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
async fn can_call_google_callback_jwt() -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // mock oauth2 server
    mock_oauth_server(&settings, true).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Get the authorization url from the server
        let auth_res = request.get("/api/oauth2/google").await;
        // Cookie for csrf token
        let auth_cookie = auth_res.cookies();
        // Get the authorization url from the response HTML
        let mut auth_url = String::new();
        let re = Regex::new(r#"([^"]*)"#).unwrap();
        for cap in re.captures_iter(&auth_res.text()) {
            auth_url = cap[1].to_string();
        }
        // Extract the state from the auth_url
        let state = Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());
        // Test the google callback with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/jwt")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.unwrap()),
            ])
            .add_cookies(auth_cookie)
            .await;
        assert_eq!(res.status_code(), 200);
        let (auth_key, auth_value) = prepare_data::auth_header(&res.text());
        let response = request
            .get("/api/user/current")
            .add_header(auth_key, auth_value)
            .await;
        assert_eq!(response.status_code(), 200);
        let login_response = response.json::<CurrentResponse>();
        assert_eq!(login_response.name, settings.profile_mock_body.name);
        assert_eq!(login_response.email, settings.profile_mock_body.email);
    })
    .await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn can_call_protect() -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // mock oauth2 server
    mock_oauth_server(&settings, true).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Get the authorization url from the server
        let auth_res = request.get("/api/oauth2/google").await;
        // Cookie for csrf token
        let auth_cookie = auth_res.cookies();
        // Get the authorization url from the response HTML
        let mut auth_url = String::new();
        let re = Regex::new(r#"([^"]*)"#).unwrap();
        for cap in re.captures_iter(&auth_res.text()) {
            auth_url = cap[1].to_string();
        }
        // Extract the state from the auth_url
        let state = Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());
        // Test the google callback with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/cookie")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.unwrap()),
            ])
            .add_cookies(auth_cookie)
            .await;
        assert_eq!(res.status_code(), 303);
        assert_eq!(
            res.headers().get("location").unwrap(),
            &settings.protected_url
        );
        // Get cookies for private jar
        let cookies = res.cookies();
        // hit the protected url
        let res = request
            .get("/api/oauth2/protected")
            .add_cookies(cookies)
            .await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(
            res.json::<LoginResponse>().name,
            settings.profile_mock_body.name
        );
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
async fn cannot_call_callback_twice_with_same_csrf_token() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = unsafe { set_default_url() }.await;
    // mock oauth2 server
    mock_oauth_server(&settings, true).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Get the authorization url from the server
        let auth_res = request.get("/api/oauth2/google").await;
        // Cookie for csrf token
        let auth_cookie = auth_res.cookies();
        // Get the authorization url from the response HTML
        let mut auth_url = String::new();
        let re = Regex::new(r#"([^"]*)"#).unwrap();
        for cap in re.captures_iter(&auth_res.text()) {
            auth_url = cap[1].to_string();
        }
        // Extract the state from the auth_url
        let state = Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());
        // Test the google callback with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/cookie")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.clone().unwrap()),
            ])
            .add_cookies(auth_cookie.clone())
            .await;
        assert_eq!(res.status_code(), 303);
        assert_eq!(
            res.headers().get("location").unwrap(),
            &settings.protected_url
        );
        // Test the google callback with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/cookie")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.clone().unwrap()),
            ])
            .add_cookies(auth_cookie)
            .await;
        assert_eq!(res.status_code(), 400);
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
pub async fn cannot_call_google_callback_without_csrf_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // Mock oauth2 server
    mock_oauth_server(&settings, false).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Test the google callback without csrf token
        let res = request
            .get("/api/oauth2/google/callback/cookie")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", "test_state".to_string()),
            ])
            .await;
        assert_eq!(res.status_code(), 400);
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
async fn cannot_call_google_callback_jwt_twice_with_same_csrf_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // mock oauth2 server
    mock_oauth_server(&settings, true).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Get the authorization url from the server
        let auth_res = request.get("/api/oauth2/google").await;
        // Cookie for csrf token
        let auth_cookie = auth_res.cookies();
        // Get the authorization url from the response HTML
        let mut auth_url = String::new();
        let re = Regex::new(r#"([^"]*)"#).unwrap();
        for cap in re.captures_iter(&auth_res.text()) {
            auth_url = cap[1].to_string();
        }
        // Extract the state from the auth_url
        let state = Url::parse(&auth_url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string());
        // Test the google callback jwt with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/jwt")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.clone().unwrap()),
            ])
            .add_cookies(auth_cookie.clone())
            .await;
        assert_eq!(res.status_code(), 200);
        // Test the google callback jwt with csrf token and token
        let res = request
            .get("/api/oauth2/google/callback/jwt")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", state.clone().unwrap()),
            ])
            .add_cookies(auth_cookie)
            .await;
        assert_eq!(res.status_code(), 400);
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
pub async fn cannot_call_google_callback_jwt_without_csrf_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = unsafe { set_default_url() }.await;
    // Mock oauth2 server
    mock_oauth_server(&settings, false).await?;
    request::<App, _, _>(|request, _ctx| async move {
        // Test the google callback jwt without csrf token
        let res = request
            .get("/api/oauth2/google/callback/jwt")
            .add_query_params(vec![
                ("code", settings.code.clone()),
                ("state", "test_state".to_string()),
            ])
            .await;
        assert_eq!(res.status_code(), 400);
    })
    .await;
    Ok(())
}
#[tokio::test]
#[serial]
pub async fn cannot_call_protect_without_cookie() -> Result<(), Box<dyn std::error::Error>> {
    request::<App, _, _>(|request, _ctx| async move {
        // hit the protected url without cookies
        let res = request.get("/api/oauth2/protected").await;
        assert_eq!(res.status_code(), 401);
    })
    .await;
    Ok(())
}
