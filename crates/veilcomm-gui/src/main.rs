//! VeilComm Web GUI Server
//!
//! Serves the glassmorphism frontend on localhost and provides REST API endpoints
//! that bridge to the VeilCommClient backend.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use veilcomm_app::VeilCommClient;

// ─── App State ───────────────────────────────────────────────

type AppState = Arc<Mutex<VeilCommClient>>;

fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("veilcomm")
}

// ─── Error Handling ──────────────────────────────────────────

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.0.to_string() });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ─── Request / Response Types ────────────────────────────────

#[derive(Deserialize)]
struct InitRequest {
    name: Option<String>,
    password: String,
}

#[derive(Serialize)]
struct InitResponse {
    fingerprint: String,
}

#[derive(Deserialize)]
struct UnlockRequest {
    password: String,
}

#[derive(Serialize)]
struct UnlockResponse {
    fingerprint: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    initialized: bool,
    unlocked: bool,
}

#[derive(Serialize)]
struct IdentityResponse {
    fingerprint: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct ContactResponse {
    fingerprint: String,
    name: Option<String>,
    verified: bool,
    unread: u32,
}

#[derive(Deserialize)]
struct AddContactRequest {
    fingerprint: String,
    name: Option<String>,
    /// Optional base64-encoded identity public key. If provided, it will be deserialized
    /// and stored as the contact's identity key. If omitted, a placeholder key is generated
    /// pending real key exchange during session establishment.
    identity_key_base64: Option<String>,
}

#[derive(Serialize)]
struct MessageResponse {
    id: String,
    outgoing: bool,
    content: String,
    timestamp: String,
    read: bool,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    text: String,
}

#[derive(Serialize)]
struct SendMessageResponse {
    id: String,
}

#[derive(Deserialize)]
struct MessagesQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct NetworkStatusResponse {
    started: bool,
    peers: usize,
    node_id: Option<String>,
    tor_enabled: bool,
    onion_address: Option<String>,
}

#[derive(Deserialize)]
struct NetworkStartRequest {
    listen_addr: String,
    bootstrap_addr: Option<String>,
    tor_socks_addr: Option<String>,
    tor_listen_port: Option<u16>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TorToggleRequest {
    enabled: bool,
    socks_addr: Option<String>,
    listen_port: Option<u16>,
    onion_address: Option<String>,
}

#[derive(Serialize)]
struct KeyBundleResponse {
    bundle_base64: String,
}

// ─── Static File Serving ─────────────────────────────────────

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

// ─── API Handlers ────────────────────────────────────────────

async fn get_status(State(client): State<AppState>) -> ApiResult<StatusResponse> {
    let client = client.lock().await;
    let initialized = client.is_initialized();
    let unlocked = client.fingerprint().is_ok();
    Ok(Json(StatusResponse {
        initialized,
        unlocked,
    }))
}

async fn post_init(
    State(client): State<AppState>,
    Json(req): Json<InitRequest>,
) -> Result<Json<InitResponse>, ApiError> {
    let mut client = client.lock().await;
    let fingerprint = client.init(&req.password, req.name.as_deref())?;
    Ok(Json(InitResponse { fingerprint }))
}

async fn post_unlock(
    State(client): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<UnlockResponse>, ApiError> {
    let mut client = client.lock().await;
    let fingerprint = client.unlock(&req.password)?;
    let name = client.name().unwrap_or(None);
    Ok(Json(UnlockResponse { fingerprint, name }))
}

async fn get_identity(State(client): State<AppState>) -> ApiResult<IdentityResponse> {
    let client = client.lock().await;
    let fingerprint = client.fingerprint()?;
    let name = client.name().unwrap_or(None);
    Ok(Json(IdentityResponse { fingerprint, name }))
}

async fn get_contacts(State(client): State<AppState>) -> ApiResult<Vec<ContactResponse>> {
    let client = client.lock().await;
    let contacts = client.list_contacts()?;
    let mut result = Vec::new();
    for c in contacts {
        let unread = client.unread_count(&c.fingerprint).unwrap_or(0);
        result.push(ContactResponse {
            fingerprint: c.fingerprint,
            name: c.name,
            verified: c.verified,
            unread,
        });
    }
    Ok(Json(result))
}

async fn post_contact(
    State(client): State<AppState>,
    Json(req): Json<AddContactRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;

    let public_key = if let Some(ref key_b64) = req.identity_key_base64 {
        // Deserialize the real identity public key provided by the frontend.
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            key_b64,
        )
        .map_err(|e| anyhow::anyhow!("Invalid base64 identity key: {}", e))?;
        bincode::deserialize::<veilcomm_core::crypto::keys::IdentityPublicKey>(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid identity public key: {}", e))?
    } else {
        // No identity key provided. Generate a placeholder key that will be replaced
        // with the real peer key during session establishment (PQXDH key exchange).
        // WARNING: This placeholder will NOT match the real peer identity. It exists
        // only so the contact record can be created before key exchange occurs.
        tracing::warn!(
            fingerprint = %req.fingerprint,
            "Adding contact without identity key - using placeholder pending key exchange"
        );
        let placeholder = veilcomm_core::crypto::keys::IdentityKeyPair::generate();
        placeholder.public_key()
    };

    client.add_contact(&req.fingerprint, req.name.as_deref(), &public_key)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn post_verify_contact(
    State(_client): State<AppState>,
    Path(_fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // TODO: Wire to client.verify_contact(&fingerprint, true) once the method is available
    // on VeilCommClient. For now, acknowledge the request so the frontend can proceed.
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_contact(
    State(client): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.remove_contact(&fingerprint)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn post_lock(State(client): State<AppState>) -> Json<serde_json::Value> {
    let mut client = client.lock().await;
    // Replace the client with a fresh instance to clear all in-memory state
    // (identity keys, sessions, etc.). The user must unlock again with their password.
    *client = VeilCommClient::new(data_dir());
    Json(serde_json::json!({ "ok": true }))
}

async fn get_messages(
    State(client): State<AppState>,
    Path(fingerprint): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> ApiResult<Vec<MessageResponse>> {
    let client = client.lock().await;
    let limit = query.limit.unwrap_or(100);
    let messages = client.get_messages(&fingerprint, limit)?;
    let result: Vec<MessageResponse> = messages
        .into_iter()
        .map(|m| MessageResponse {
            id: m.id,
            outgoing: m.outgoing,
            content: String::from_utf8_lossy(&m.content).to_string(),
            timestamp: m.timestamp.to_rfc3339(),
            read: m.read,
        })
        .collect();
    Ok(Json(result))
}

async fn post_message(
    State(client): State<AppState>,
    Path(fingerprint): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    let mut client = client.lock().await;

    // If we have a network connection, try sending over the network
    if client.has_session(&fingerprint) {
        let encrypted = client.send_message(&fingerprint, &req.text)?;
        return Ok(Json(SendMessageResponse {
            id: encrypted.message_id,
        }));
    }

    // No active session: we cannot encrypt or store the message without a session.
    // Return an error so the frontend can inform the user.
    Err(ApiError(anyhow::anyhow!(
        "No active session with this contact. Establish a connection first."
    )))
}

async fn post_mark_read(
    State(client): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.mark_read(&fingerprint)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_network_status(State(client): State<AppState>) -> ApiResult<NetworkStatusResponse> {
    let client = client.lock().await;
    let node_id = client.node_id().map(hex::encode);
    let started = node_id.is_some();
    let (tor_enabled, onion_address) = client.tor_status();
    Ok(Json(NetworkStatusResponse {
        started,
        peers: 0,
        node_id,
        tor_enabled,
        onion_address,
    }))
}

async fn post_network_start(
    State(client): State<AppState>,
    Json(req): Json<NetworkStartRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // NOTE: We hold a tokio::sync::Mutex guard across the `.await` below. This is safe
    // because tokio::sync::Mutex (unlike std::sync::Mutex) is designed to be held across
    // await points. The trade-off is that other requests will be blocked while network
    // startup is in progress. For the initial version this is acceptable; a future
    // improvement would split the client into separate locks for network vs data access.
    let mut client = client.lock().await;
    let listen_addr: SocketAddr = req
        .listen_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address: {}", e))?;

    let bootstrap_peers: Vec<SocketAddr> = if let Some(ref addr) = req.bootstrap_addr {
        if addr.is_empty() {
            vec![]
        } else {
            vec![addr
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid bootstrap address: {}", e))?]
        }
    } else {
        vec![]
    };

    // Build Tor config if a SOCKS address was provided
    let tor_config = req.tor_socks_addr.as_ref().map(|socks_addr_str| {
        let socks_addr: SocketAddr = socks_addr_str
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:9050".parse().unwrap());
        veilcomm_network::TorConfig {
            socks_addr,
            enabled: true,
            listen_port: req.tor_listen_port.unwrap_or(9051),
        }
    });

    client.start_network(listen_addr, &bootstrap_peers, tor_config).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn post_tor_config(
    State(client): State<AppState>,
    Json(req): Json<TorToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    if let Some(onion_addr) = req.onion_address {
        client.set_onion_address(onion_addr);
    }
    Ok(Json(serde_json::json!({ "ok": true, "tor_enabled": req.enabled })))
}

async fn post_network_stop() -> Json<serde_json::Value> {
    // NetworkService doesn't have a stop method currently,
    // but we acknowledge the request
    Json(serde_json::json!({ "ok": true, "note": "Network will stop when process exits" }))
}

async fn get_key_bundle(
    State(client): State<AppState>,
) -> Result<Json<KeyBundleResponse>, ApiError> {
    let client = client.lock().await;
    let bundle = client.get_key_bundle()?;
    let bytes =
        bincode::serialize(&bundle).map_err(|e| anyhow::anyhow!("Serialize error: {}", e))?;
    let bundle_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
    Ok(Json(KeyBundleResponse { bundle_base64 }))
}

// ─── Helpers ─────────────────────────────────────────────────

#[allow(dead_code)]
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─── Main ────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let client = VeilCommClient::new(data_dir());
    let state: AppState = Arc::new(Mutex::new(client));

    let app = Router::new()
        // Frontend
        .route("/", get(serve_index))
        // Status
        .route("/api/status", get(get_status))
        // Auth
        .route("/api/init", post(post_init))
        .route("/api/unlock", post(post_unlock))
        // Identity
        .route("/api/identity", get(get_identity))
        // Contacts
        .route("/api/contacts", get(get_contacts))
        .route("/api/contacts", post(post_contact))
        .route("/api/contacts/{fingerprint}", delete(delete_contact))
        .route(
            "/api/contacts/{fingerprint}/verify",
            post(post_verify_contact),
        )
        // Lock
        .route("/api/lock", post(post_lock))
        // Messages
        .route("/api/messages/{fingerprint}", get(get_messages))
        .route("/api/messages/{fingerprint}", post(post_message))
        .route("/api/messages/{fingerprint}/read", post(post_mark_read))
        // Network
        .route("/api/network/status", get(get_network_status))
        .route("/api/network/start", post(post_network_start))
        .route("/api/network/stop", post(post_network_stop))
        .route("/api/network/tor", post(post_tor_config))
        // Keys
        .route("/api/key-bundle", get(get_key_bundle))
        .with_state(state);

    // Try port 3000 first; fall back to an OS-assigned port if it's already in use.
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:3000").await {
        Ok(l) => l,
        Err(_) => {
            tracing::warn!("Port 3000 in use, binding to random available port");
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
        }
    };
    let addr = listener.local_addr().unwrap();
    tracing::info!("VeilComm GUI starting at http://{}", addr);

    // Open browser at the actual bound address
    let url = format!("http://{}", addr);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Err(e) = open::that(&url) {
            tracing::warn!("Could not open browser: {}", e);
        }
    });

    tracing::info!("Listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
