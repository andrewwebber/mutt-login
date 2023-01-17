use std::io::BufRead;

use clap::{Parser, Subcommand};
use oauth2::reqwest::http_client;
use oauth2::{basic::BasicClient, revocation::StandardRevocableToken, TokenResponse};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RefreshToken,
    Scope, TokenUrl,
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Client ID
    #[arg(long)]
    client_id: String,
    /// Client Secret
    #[arg(long)]
    client_secret: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Signin
    SignIn,
    /// Refresh token
    Refresh {
        /// Existing refresh token
        #[arg(short, long)]
        token: String,
    },
}

fn main() {
    let cli = Args::parse();
    match cli {
        Args {
            client_id,
            client_secret,
            command: Commands::SignIn,
        } => {
            let client = basic_client(client_id, client_secret);

            // Generate the authorization URL to which we'll redirect the user.
            let (authorize_url, _csrf_state) = client
                .authorize_url(CsrfToken::new_random)
                .add_scope(Scope::new("https://mail.google.com/".to_string()))
                .url();

            println!("Open this URL in your browser:\n{}\n", authorize_url);

            let stdin = std::io::stdin();
            let mut iterator = stdin.lock().lines();
            let code = iterator.next().unwrap().unwrap().trim().to_string();

            let token_response = client
                .exchange_code(AuthorizationCode::new(code))
                .request(http_client);

            let token_response = token_response.unwrap();
            let token_response = serde_json::to_string(&token_response).unwrap();

            println!("{token_response}");
        }
        Args {
            client_id,
            client_secret,
            command: Commands::Refresh { token },
        } => {
            let client = basic_client(client_id, client_secret);
            let token_response = client
                .exchange_refresh_token(&RefreshToken::new(token.trim().to_string()))
                .request(http_client);

            let token_response = token_response.unwrap().access_token().secret().to_string();
            println!("{token_response}");
        }
    }
}

type Client = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::basic::BasicTokenType,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
>;

fn basic_client(client_id: String, client_secret: String) -> Client {
    let google_client_id = ClientId::new(client_id);
    let google_client_secret = ClientSecret::new(client_secret);
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Google OAuth2 process.
    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string()).expect("Invalid redirect URL"),
    )
    .set_auth_type(oauth2::AuthType::RequestBody)
}
