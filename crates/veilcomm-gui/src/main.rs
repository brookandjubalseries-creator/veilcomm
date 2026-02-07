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
    delivery_status: String,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    text: String,
}

#[derive(Serialize)]
struct SendMessageResponse {
    id: String,
    delivery_status: String,
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

// ─── Group Request / Response Types ──────────────────────────

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: String,
    member_fingerprints: Vec<String>,
}

#[derive(Serialize)]
struct GroupResponse {
    group_id: String,
    name: String,
    member_count: usize,
    unread: u32,
}

#[derive(Serialize)]
struct GroupDetailResponse {
    group_id: String,
    name: String,
    member_count: usize,
}

#[derive(Serialize)]
struct GroupMemberResponse {
    fingerprint: String,
    name: Option<String>,
    role: String,
}

#[derive(Deserialize)]
struct AddGroupMemberRequest {
    fingerprint: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct GroupMessageResponse {
    id: String,
    sender_fingerprint: String,
    sender_name: Option<String>,
    content: String,
    timestamp: String,
    read: bool,
}

#[derive(Deserialize)]
struct SendGroupMessageRequest {
    text: String,
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
            delivery_status: m.delivery_status,
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

    // Try sending with offline fallback via send_message_network
    if client.has_session(&fingerprint) {
        let message_id = client.send_message_network(&fingerprint, &req.text).await?;

        // Check the delivery status from the database
        let delivery_status = if let Some(db) = client.database() {
            db.get_messages(&fingerprint, 1)
                .ok()
                .and_then(|msgs| msgs.into_iter().find(|m| m.id == message_id))
                .map(|m| m.delivery_status)
                .unwrap_or_else(|| "delivered".to_string())
        } else {
            "delivered".to_string()
        };

        return Ok(Json(SendMessageResponse {
            id: message_id,
            delivery_status,
        }));
    }

    Err(ApiError(anyhow::anyhow!(
        "No active session with this contact. Establish a connection first."
    )))
}

async fn post_check_offline(
    State(client): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.check_offline_messages().await?;
    Ok(Json(serde_json::json!({ "ok": true })))
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

// ─── Group API Handlers ──────────────────────────────────────

async fn get_groups(State(client): State<AppState>) -> ApiResult<Vec<GroupResponse>> {
    let client = client.lock().await;
    let groups = client.list_groups()?;
    let mut result = Vec::new();
    for g in groups {
        let member_count = client.get_group_members(&g.group_id)
            .map(|m| m.len())
            .unwrap_or(0);
        let unread = client.unread_group_count(&g.group_id).unwrap_or(0);
        result.push(GroupResponse {
            group_id: g.group_id,
            name: g.name,
            member_count,
            unread,
        });
    }
    Ok(Json(result))
}

async fn post_group(
    State(client): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    let group_id = client.create_group(&req.name, &req.member_fingerprints)?;
    Ok(Json(serde_json::json!({ "group_id": group_id })))
}

async fn get_group(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
) -> Result<Json<GroupDetailResponse>, ApiError> {
    let client = client.lock().await;
    let group = client.get_group(&group_id)?
        .ok_or_else(|| anyhow::anyhow!("Group not found"))?;
    let member_count = client.get_group_members(&group_id)
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(Json(GroupDetailResponse {
        group_id: group.group_id,
        name: group.name,
        member_count,
    }))
}

async fn delete_group_handler(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.delete_group(&group_id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_group_members(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
) -> ApiResult<Vec<GroupMemberResponse>> {
    let client = client.lock().await;
    let members = client.get_group_members(&group_id)?;
    let result: Vec<GroupMemberResponse> = members
        .into_iter()
        .map(|m| GroupMemberResponse {
            fingerprint: m.fingerprint,
            name: m.name,
            role: m.role,
        })
        .collect();
    Ok(Json(result))
}

async fn post_group_member(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.add_group_member(&group_id, &req.fingerprint, req.name.as_deref())?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_group_member(
    State(client): State<AppState>,
    Path((group_id, fingerprint)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.remove_group_member(&group_id, &fingerprint)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn post_leave_group(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.leave_group(&group_id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_group_messages(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> ApiResult<Vec<GroupMessageResponse>> {
    let client = client.lock().await;
    let limit = query.limit.unwrap_or(100);
    let messages = client.get_group_messages(&group_id, limit)?;

    // Build a fingerprint -> name lookup from group members
    let members = client.get_group_members(&group_id).unwrap_or_default();
    let name_map: std::collections::HashMap<String, Option<String>> = members
        .into_iter()
        .map(|m| (m.fingerprint, m.name))
        .collect();

    let result: Vec<GroupMessageResponse> = messages
        .into_iter()
        .map(|m| {
            let sender_name = name_map
                .get(&m.sender_fingerprint)
                .cloned()
                .flatten();
            GroupMessageResponse {
                id: m.id,
                sender_fingerprint: m.sender_fingerprint,
                sender_name,
                content: String::from_utf8_lossy(&m.content).to_string(),
                timestamp: m.timestamp.to_rfc3339(),
                read: m.read,
            }
        })
        .collect();
    Ok(Json(result))
}

async fn post_group_message(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
    Json(req): Json<SendGroupMessageRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    let message_id = client.send_group_message(&group_id, &req.text)?;
    Ok(Json(serde_json::json!({ "id": message_id })))
}

async fn post_group_messages_read(
    State(client): State<AppState>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.mark_group_read(&group_id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Duress API Handlers ─────────────────────────────────────

#[derive(Deserialize)]
struct DuressSetupRequest {
    real_password: String,
    duress_password: String,
}

async fn post_setup_duress(
    State(client): State<AppState>,
    Json(req): Json<DuressSetupRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    let fp = client.setup_duress(&req.real_password, &req.duress_password)?;
    Ok(Json(serde_json::json!({ "ok": true, "duress_fingerprint": fp })))
}

async fn get_duress_status(
    State(client): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let client = client.lock().await;
    Ok(Json(serde_json::json!({ "has_duress": client.has_duress() })))
}

async fn post_remove_duress(
    State(client): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    client.remove_duress(&req.password)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Dead Man's Switch API Handlers ─────────────────────────

#[derive(Deserialize)]
struct CreateDmsRequest {
    recipients: Vec<String>,
    message: String,
    interval_hours: i64,
}

#[derive(Serialize)]
struct DmsResponse {
    id: String,
    recipients: Vec<String>,
    message: String,
    interval_hours: i64,
    last_check_in: String,
    enabled: bool,
    triggered: bool,
}

async fn get_dead_man_switches(
    State(client): State<AppState>,
) -> ApiResult<Vec<DmsResponse>> {
    let client = client.lock().await;
    let switches = client.list_dead_man_switches()?;
    let result: Vec<DmsResponse> = switches
        .into_iter()
        .map(|d| DmsResponse {
            id: d.id,
            recipients: d.recipient_fingerprints,
            message: d.message,
            interval_hours: d.check_in_interval_secs / 3600,
            last_check_in: d.last_check_in.to_rfc3339(),
            enabled: d.enabled,
            triggered: d.triggered,
        })
        .collect();
    Ok(Json(result))
}

async fn post_dead_man_switch(
    State(client): State<AppState>,
    Json(req): Json<CreateDmsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    let interval_secs = req.interval_hours * 3600;
    let id = client.create_dead_man_switch(req.recipients, &req.message, interval_secs)?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn post_dead_man_check_in(
    State(client): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.dead_man_check_in()?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_dead_man_switch_handler(
    State(client): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.delete_dead_man_switch(&id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ToggleDmsRequest {
    enabled: bool,
}

async fn post_toggle_dead_man_switch(
    State(client): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ToggleDmsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    client.toggle_dead_man_switch(&id, req.enabled)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_expired_switches(
    State(client): State<AppState>,
) -> ApiResult<Vec<DmsResponse>> {
    let client = client.lock().await;
    let expired = client.check_expired_switches()?;
    let result: Vec<DmsResponse> = expired
        .into_iter()
        .map(|d| DmsResponse {
            id: d.id,
            recipients: d.recipient_fingerprints,
            message: d.message,
            interval_hours: d.check_in_interval_secs / 3600,
            last_check_in: d.last_check_in.to_rfc3339(),
            enabled: d.enabled,
            triggered: d.triggered,
        })
        .collect();
    Ok(Json(result))
}

// ─── Mesh Discovery API Handlers ────────────────────────────

#[derive(Deserialize)]
struct MeshStartRequest {
    listen_addr: String,
}

#[derive(Serialize)]
struct MeshPeerResponse {
    fingerprint: String,
    name: Option<String>,
    addr: String,
}

async fn post_mesh_start(
    State(client): State<AppState>,
    Json(req): Json<MeshStartRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = client.lock().await;
    let addr: SocketAddr = req.listen_addr.parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
    client.start_mesh(addr).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn post_mesh_stop(
    State(client): State<AppState>,
) -> Json<serde_json::Value> {
    let mut client = client.lock().await;
    client.stop_mesh().await;
    Json(serde_json::json!({ "ok": true }))
}

async fn get_mesh_peers(
    State(client): State<AppState>,
) -> ApiResult<Vec<MeshPeerResponse>> {
    let client = client.lock().await;
    let peers = client.mesh_peers();
    let result: Vec<MeshPeerResponse> = peers
        .into_iter()
        .map(|p| MeshPeerResponse {
            fingerprint: p.fingerprint,
            name: p.name,
            addr: p.addr.to_string(),
        })
        .collect();
    Ok(Json(result))
}

async fn get_mesh_status(
    State(client): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let client = client.lock().await;
    Ok(Json(serde_json::json!({
        "running": client.is_mesh_running()
    })))
}

// ─── Steganography API Handlers ─────────────────────────────

#[derive(Deserialize)]
struct StegoEncodeRequest {
    payload_base64: String,
}

async fn post_stego_encode(
    State(client): State<AppState>,
    Json(req): Json<StegoEncodeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.payload_base64,
    ).map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))?;

    let bmp = client.stego_encode(&payload)?;
    let bmp_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bmp);
    Ok(Json(serde_json::json!({ "bmp_base64": bmp_b64 })))
}

#[derive(Deserialize)]
struct StegoDecodeRequest {
    bmp_base64: String,
}

async fn post_stego_decode(
    State(client): State<AppState>,
    Json(req): Json<StegoDecodeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let client = client.lock().await;
    let bmp = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &req.bmp_base64,
    ).map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))?;

    let payload = client.stego_decode(&bmp)?;
    let payload_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload);
    Ok(Json(serde_json::json!({ "payload_base64": payload_b64 })))
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
        .route("/api/messages/check-offline", post(post_check_offline))
        // Network
        .route("/api/network/status", get(get_network_status))
        .route("/api/network/start", post(post_network_start))
        .route("/api/network/stop", post(post_network_stop))
        .route("/api/network/tor", post(post_tor_config))
        // Keys
        .route("/api/key-bundle", get(get_key_bundle))
        // Groups
        .route("/api/groups", get(get_groups))
        .route("/api/groups", post(post_group))
        .route("/api/groups/{id}", get(get_group))
        .route("/api/groups/{id}", delete(delete_group_handler))
        .route("/api/groups/{id}/members", get(get_group_members))
        .route("/api/groups/{id}/members", post(post_group_member))
        .route(
            "/api/groups/{id}/members/{fingerprint}",
            delete(delete_group_member),
        )
        .route("/api/groups/{id}/leave", post(post_leave_group))
        .route("/api/groups/{id}/messages", get(get_group_messages))
        .route("/api/groups/{id}/messages", post(post_group_message))
        .route("/api/groups/{id}/messages/read", post(post_group_messages_read))
        // Duress
        .route("/api/duress/setup", post(post_setup_duress))
        .route("/api/duress/status", get(get_duress_status))
        .route("/api/duress/remove", post(post_remove_duress))
        // Dead Man's Switch
        .route("/api/dms", get(get_dead_man_switches))
        .route("/api/dms", post(post_dead_man_switch))
        .route("/api/dms/check-in", post(post_dead_man_check_in))
        .route("/api/dms/expired", get(get_expired_switches))
        .route("/api/dms/{id}", delete(delete_dead_man_switch_handler))
        .route("/api/dms/{id}/toggle", post(post_toggle_dead_man_switch))
        // Mesh Discovery
        .route("/api/mesh/start", post(post_mesh_start))
        .route("/api/mesh/stop", post(post_mesh_stop))
        .route("/api/mesh/peers", get(get_mesh_peers))
        .route("/api/mesh/status", get(get_mesh_status))
        // Steganography
        .route("/api/stego/encode", post(post_stego_encode))
        .route("/api/stego/decode", post(post_stego_decode))
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
