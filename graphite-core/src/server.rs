//! HTTP server for Graphite Core — exposes the verification API over HTTP.
//!
//! Production features:
//! - API-key auth (`GRAPHITE_API_KEY` env; Bearer token, constant-time
//!   comparison), required by default: the server refuses to start without a
//!   key unless `GRAPHITE_DEV_MODE=1` is set, and then only on loopback (and
//!   only to requests whose `Host` is a loopback name).
//! - Per-IP rate limiting (`GRAPHITE_RATE_LIMIT` requests/second, default 30)
//!   on every route but `/health`
//! - CORS: denied by default; allow origins via `GRAPHITE_CORS_ORIGINS`
//!   (comma-separated, no wildcard). Servers calling the API don't need CORS
//!   at all.
//! - Load shedding: verifications and every other route draw on separate
//!   in-flight pools; `/health` on neither
//! - Request body size limit (1 MB max — prevents DoS via large payloads)
//! - Request timeout (10s max — prevents slow-loris attacks)
//! - Optional live L3 simulation: `GRAPHITE_RPC_URL` attaches a Solana RPC
//!   client so `simulateTransaction` actually runs (real compute usage feeds
//!   the trusted simulation baseline accumulator).
//! - Durability: `GRAPHITE_DATA_DIR` (default `./graphite-data`) holds the
//!   semantic-graph snapshot and an append-only `audit.jsonl` written after
//!   every verification.
//! - Graceful shutdown on SIGTERM/SIGINT (container-friendly)

use crate::account_resolution::AccountResolutionError;
use crate::durable::{
    audit_path, AuditErrorRecord, AuditLog, AuditRecord, AuditSelector, LifecycleEvent,
    LifecycleEventRecord, VerdictOnRecord, VerificationKey, VerificationKeyKind,
};
use crate::operator_boundary::{enforce_wallet_profile, env_number, OperatorPolicy};
#[cfg(test)]
use crate::operator_boundary::{env_flag, parse_pinned_profile};
use crate::verification::{GraphiteCore, VerificationError, VerificationInput, VerificationResult};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::signal;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

/// Maximum request body size (1 MB). Verification inputs are small —
/// 10 accounts x 44 bytes + metadata ~= 2 KB. 1 MB is generous.
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// A base58 Solana signature is 64 bytes: 87–88 characters.
const MAX_SIGNATURE_CHARS: usize = 90;
/// `audit_trail_id` (a `gr-<uuid>`) and `reported_by` (an operator-meaningful
/// name) on `/audit/event`.
const MAX_LIFECYCLE_ID_CHARS: usize = 128;
/// Free-form `detail` on `/audit/event`: a slot, a failure reason. The same
/// bound the trail applies on disk.
use crate::durable::MAX_LIFECYCLE_DETAIL_CHARS;

/// The shape of a `transaction_sha256`: what `hex::encode(Sha256::digest(..))`
/// produces, and nothing else.
/// A Solana transaction signature is 64 bytes, base58: 86 to 88 characters
/// of the base58 alphabet that decode to exactly 64 bytes.
fn signature_shape(s: &str) -> Result<(), String> {
    match bs58::decode(s).into_vec() {
        Ok(bytes) if bytes.len() == 64 => Ok(()),
        Ok(bytes) => Err(format!(
            "signature decodes to {} bytes; a Solana signature is 64",
            bytes.len()
        )),
        Err(_) => Err("signature is not base58".to_string()),
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Request timeout. Verification should complete in <1ms; 10s is
/// generous. It starts once a request HEAD has been read: the head itself is
/// bounded by `HEADER_READ_TIMEOUT`, and it is that bound, with the
/// connection cap, that stops a slow-loris client.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client may take to send a complete request head, and how long
/// an idle keep-alive connection is held waiting for the next one (A4-03,
/// 2026-09-29 audit).
///
/// `REQUEST_TIMEOUT` is a tower layer, and a tower layer only runs once a
/// request exists. axum's `serve` gave hyper no timer, so hyper's own
/// head-read timeout was inert ("has default, but no timer set"): a client
/// that sent half a request line — or nothing — held a socket, a descriptor
/// and a task indefinitely, before auth, the rate limiter or the body timeout
/// could see it. The server now runs its own accept loop with a timer.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The most TCP connections held open at once (A4-03). A connection past the
/// cap is closed at accept, before a byte is read, so descriptor exhaustion
/// cannot take `accept` down for everyone. Raise with
/// `GRAPHITE_MAX_CONNECTIONS`.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// The most connections one peer may hold open at once when Graphite faces
/// clients directly (review of the 2026-09-29 audit's fix, F8). The global
/// cap alone let one client hold all of them: ~205 half-sent heads a second,
/// each waiting out the header timeout, and every other client was closed
/// at accept. Behind a trusted proxy every connection comes from the proxy,
/// so the default there is no per-peer cap (the proxy enforces one); set
/// `GRAPHITE_MAX_CONNECTIONS_PER_IP` to choose either way (0 = no cap).
const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 64;

/// How long one connection may stay open, whatever it is doing
/// (`GRAPHITE_CONNECTION_LIFETIME_SECS`). W21 (external review, verified
/// 2026-10-03): nothing bounded a connection once its request head had
/// arrived. A client that asked for `/manifests` and never read the answer,
/// or that kept an idle keep-alive open, held its connection slot and its
/// per-peer slot indefinitely, so a handful of addresses could fill the
/// 1,024-connection cap. A request is bounded by `REQUEST_TIMEOUT` (10 s), so
/// this cuts only connections that are stalled or idle; a client reconnects.
const DEFAULT_CONNECTION_LIFETIME: Duration = Duration::from_secs(120);

/// How many peers' worth of connections one IPv6 /48 may hold together
/// (audit 2026-10-20, L6).
///
/// The per-peer cap is keyed like the rate limiter, per /64, because one host
/// is routinely handed a whole /64. A /56 — what many ISPs hand a single
/// customer — is 256 /64s, so one subscriber could hold 256 × 64 connections,
/// past the whole 1,024 default: the per-peer cap did not bound them. A /48
/// (one site) now holds at most `SITE_CONNECTION_FACTOR` × the per-peer cap
/// across all of its /64s: 256 at the defaults, a quarter of the global cap,
/// which still leaves room for a site with many hosts behind it. Wider
/// allocations (a /32 holder has 65,536 /48s) are bounded only by the global
/// cap; that cap is what keeps descriptors from running out, and this one is
/// fairness between clients. IPv4 is keyed per address, as before: a /24 is
/// 256 real addresses an attacker must actually hold.
const SITE_CONNECTION_FACTOR: usize = 4;

/// The /48 an IPv6 peer belongs to, or `None` for IPv4 (and IPv4-mapped
/// IPv6), which has no site aggregate.
fn site_key(ip: IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(_) => None,
            None => {
                let s = v6.segments();
                Some(IpAddr::V6(std::net::Ipv6Addr::new(
                    s[0], s[1], s[2], 0, 0, 0, 0, 0,
                )))
            }
        },
    }
}

/// Open connections per peer (keyed like the rate limiter: IPv6 per /64) and
/// per IPv6 site (/48), released by [`PeerSlot`] on drop.
#[derive(Default)]
struct PeerConnections {
    open: std::sync::Mutex<PeerCounts>,
}

/// The two tallies. Separate maps: a /64 key whose fourth segment is zero is
/// the same `IpAddr` as its /48 key.
#[derive(Default)]
struct PeerCounts {
    peers: HashMap<IpAddr, usize>,
    sites: HashMap<IpAddr, usize>,
}

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerRefusal {
    /// The peer (/64) already holds its cap.
    Peer,
    /// The peer's /48 already holds `SITE_CONNECTION_FACTOR` × the cap.
    Site,
}

/// One peer's claim on a connection slot; returns it when dropped.
struct PeerSlot {
    peers: Arc<PeerConnections>,
    key: IpAddr,
    site: Option<IpAddr>,
}

impl PeerConnections {
    /// A slot for `ip`, unless its peer already holds `limit` or its /48
    /// already holds `SITE_CONNECTION_FACTOR × limit` (0 = no limit; the
    /// connection is still counted, so the maps stay exact).
    fn claim(self: &Arc<Self>, ip: IpAddr, limit: usize) -> Result<PeerSlot, PeerRefusal> {
        let key = rate_limit_key(ip);
        let site = site_key(ip);
        let mut open = self.lock();
        if limit != 0 {
            if open.peers.get(&key).copied().unwrap_or(0) >= limit {
                return Err(PeerRefusal::Peer);
            }
            if let Some(site) = site {
                let site_limit = limit.saturating_mul(SITE_CONNECTION_FACTOR);
                if open.sites.get(&site).copied().unwrap_or(0) >= site_limit {
                    return Err(PeerRefusal::Site);
                }
            }
        }
        *open.peers.entry(key).or_insert(0) += 1;
        if let Some(site) = site {
            *open.sites.entry(site).or_insert(0) += 1;
        }
        drop(open);
        Ok(PeerSlot {
            peers: Arc::clone(self),
            key,
            site,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PeerCounts> {
        match self.open.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        fn release(map: &mut HashMap<IpAddr, usize>, key: &IpAddr) {
            if let Some(n) = map.get_mut(key) {
                *n -= 1;
                if *n == 0 {
                    map.remove(key);
                }
            }
        }
        let mut open = self.peers.lock();
        release(&mut open.peers, &self.key);
        if let Some(site) = &self.site {
            release(&mut open.sites, site);
        }
    }
}

/// At most one log line per window for one class of caller-triggerable
/// refusal, carrying how many were suppressed since the last (audit
/// 2026-10-20, L4).
///
/// The connection caps and load shedding are refusals any client can cause
/// on demand, and each wrote a line: a flood of connections was a flood of
/// log lines, the cheapest way to fill the operator's disk and bury real
/// faults. The refusals are still counted exactly (in `/metrics` where they
/// are metrics); the log keeps one line per window with the count.
struct LogThrottle {
    window_ms: u64,
    /// Milliseconds since `process_millis`'s epoch of the last emitted line;
    /// 0 = never.
    last_ms: std::sync::atomic::AtomicU64,
    suppressed: std::sync::atomic::AtomicU64,
}

/// The window for the server's refusal-log throttles.
const REFUSAL_LOG_WINDOW_MS: u64 = 10_000;

impl LogThrottle {
    const fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            last_ms: std::sync::atomic::AtomicU64::new(0),
            suppressed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// `Some(n)` when a line should be written now, `n` being how many were
    /// suppressed since the last one; `None` when this one is suppressed.
    fn admit(&self) -> Option<u64> {
        use std::sync::atomic::Ordering::Relaxed;
        let now = process_millis();
        let last = self.last_ms.load(Relaxed);
        if last != 0 && now.saturating_sub(last) < self.window_ms {
            self.suppressed.fetch_add(1, Relaxed);
            return None;
        }
        if self
            .last_ms
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_err()
        {
            // Another thread took this window's line.
            self.suppressed.fetch_add(1, Relaxed);
            return None;
        }
        Some(self.suppressed.swap(0, Relaxed))
    }
}

/// Monotonic milliseconds since first use, never 0.
fn process_millis() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// `" (N more like it since the last line)"` for a throttled log line, or
/// nothing.
fn suppressed_note(n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(" ({n} more like it since the last line)")
    }
}

/// How many verifications may be in flight at once before the server sheds
/// load.
///
/// Measured 2026-09-08 against the shipped container with a live devnet RPC: 50
/// truly-concurrent verifications produced 33 answers and 17 bare `408`s over
/// 26 seconds. The RPC budget bounds each request, but nothing bounded how many
/// requests could be waiting on the same upstream at once, so the server
/// accepted every one of them and let a third expire at the deadline.
///
/// That is the same failure the RPC budget fixed, arriving from a different
/// direction: a request that dies at the timeout carries no verdict, no layer
/// report and no audit record. Under load — exactly when an operator most needs
/// to know what the gate decided — Graphite went quiet.
///
/// Shedding is the honest alternative. A `503` with `Retry-After` tells the
/// caller the server is at capacity and when to come back; a `408` tells them
/// the server was slow at their request specifically, which invites an
/// immediate retry and makes the overload worse. The distinction from the
/// per-IP `429` is deliberate too: `429` means "you are asking too often",
/// `503` means "everyone is". An operator reading the metrics can tell a noisy
/// client from a saturated instance.
///
/// The default is sized so the in-flight set can clear well inside
/// REQUEST_TIMEOUT at the latency a healthy RPC gives (~0.4s per verification,
/// measured on the same container). Raise it with `GRAPHITE_MAX_CONCURRENT`
/// when the upstream RPC can sustain more.
const DEFAULT_MAX_CONCURRENT_VERIFICATIONS: usize = 32;

/// How many requests to the routes that are NOT verifications — the
/// dashboard's `/api/*`, `/audit/event`, `/manifests`, `/metrics` and
/// `/admin/*` — may be in flight at once (audit 2026-10-20, M12).
///
/// They used to take the verification permits. A dashboard read waits for
/// one of the four archive-scan slots, and a lifecycle report for the
/// lifecycle lock, holding its permit the whole time, so 32 slow dashboard
/// polls against a large trail held every permit and `/verify` was shed with
/// 503 while nothing was being verified. They now draw on this separate pool
/// and can never take a verification's capacity; when it is full they are
/// shed the same way, counted apart
/// (`graphite_auxiliary_load_shed_total`). `/health` draws on neither.
const MAX_CONCURRENT_AUXILIARY: usize = 16;

/// Dashboard series caps: the confidence chart and the violations list only
/// ever materialize this many points per request (memory stays bounded as
/// the audit log grows); the response still reports the true totals.
const CONFIDENCE_SERIES_CAP: usize = 500;
const VIOLATIONS_CAP: usize = 200;

/// Shared application state.
///
/// Cloned by axum on every `State` extraction and by every
/// `from_fn_with_state` middleware — four or more times per request. So the
/// two large immutable members are behind `Arc` (Round 11): until then each
/// clone deep-copied the whole manifest registry (every protocol manifest, a
/// `BTreeMap` of nested structures) and the community registry engine, and a
/// `/health` that computes in microseconds answered in ~100 ms on loopback.
/// Measured in-process: 95 ms → 1 ms per request. Every handler uses `&self`
/// methods; the mutable state inside `GraphiteCore` is already interior.
#[derive(Clone)]
struct AppState {
    core: Arc<GraphiteCore>,
    /// Bearer API key; `None` only under `GRAPHITE_DEV_MODE=1` on loopback.
    api_key: Option<Arc<String>>,
    /// The OPERATOR key for `/admin/*` (`GRAPHITE_ADMIN_API_KEY`), distinct
    /// from the verify key. `None` disables the operator surface entirely
    /// (Round 19, F-19-13).
    admin_key: Option<Arc<String>>,
    /// The READ key (`GRAPHITE_READ_API_KEY`, Round 30): opens the read-only
    /// routes — `/metrics`, `/manifests`, `/api/*` — and nothing that
    /// verifies, records or acts. The dashboard holds this one, so a leaked
    /// dashboard key cannot submit verifications or lifecycle reports.
    /// `None` leaves those routes on the verify key alone, as before.
    read_key: Option<Arc<String>>,
    audit: Option<AuditLog>,
    /// Community Manifest Registry engine (read-only dashboard view — P4).
    registry_engine: Arc<crate::manifest_registry::ManifestRegistryEngine>,
    rate: RateLimiter,
    /// Only honor `X-Forwarded-For` when behind a trusted proxy.
    trust_proxy_hops: u8,
    /// Operational counters exported at `/metrics`.
    metrics: Metrics,
    /// Bounds how many verifications may be in flight at once. See
    /// `DEFAULT_MAX_CONCURRENT_VERIFICATIONS`: without it the server accepts
    /// work it cannot finish inside REQUEST_TIMEOUT and a third of it dies with
    /// no verdict and no audit record.
    inflight: Arc<tokio::sync::Semaphore>,
    /// The configured limit, reported to a shed caller so they can size their
    /// own concurrency instead of guessing.
    inflight_limit: usize,
    /// The separate pool for every route that is not a verification (see
    /// `MAX_CONCURRENT_AUXILIARY`), so those can never hold `inflight`.
    aux_inflight: Arc<tokio::sync::Semaphore>,
    /// Operator-pinned wallet profile; when set it overrides the request body.
    pinned_profile: Option<crate::policy_engine::WalletProfile>,
    /// Opt-out allowing a caller-supplied profile weaker than any built-in.
    allow_permissive_profiles: bool,
}

/// Process-lifetime counters for `/metrics`.
///
/// Deliberately a small set that is genuinely maintained at the point each
/// event happens — a metrics surface that looks comprehensive but is never
/// incremented is worse than none, because operators build alerts on it.
#[derive(Clone, Default)]
struct Metrics {
    verify_requests: Arc<std::sync::atomic::AtomicU64>,
    verify_approved: Arc<std::sync::atomic::AtomicU64>,
    verify_blocked: Arc<std::sync::atomic::AtomicU64>,
    verify_errors: Arc<std::sync::atomic::AtomicU64>,
    auth_failures: Arc<std::sync::atomic::AtomicU64>,
    rate_limited: Arc<std::sync::atomic::AtomicU64>,
    /// Requests shed because the server was already at its in-flight limit.
    load_shed: Arc<std::sync::atomic::AtomicU64>,
    /// Non-verification requests shed because their own pool was full
    /// (audit 2026-10-20, M12).
    aux_load_shed: Arc<std::sync::atomic::AtomicU64>,
    /// Requests to `/verify/execution`, `/audit/event` and `/admin/quarantine`
    /// refused as malformed, 400 or 422 (audit 2026-10-20). `/verify`'s own
    /// refusals are in `verify_errors`.
    request_rejections: Arc<std::sync::atomic::AtomicU64>,
    lifecycle_events: Arc<std::sync::atomic::AtomicU64>,
    /// Lifecycle events reported against a content_hash whose most recent
    /// verification was a BLOCK: a signing, submission or confirmation of a
    /// transaction Graphite refused. The gate being bypassed, visible at
    /// the report rather than after L8.
    lifecycle_on_blocked: Arc<std::sync::atomic::AtomicU64>,
    /// Lifecycle events reported against a content_hash with no
    /// verification on record anywhere in the trail.
    lifecycle_unverified: Arc<std::sync::atomic::AtomicU64>,
    /// L8 reconciliations performed (`/verify/execution`).
    execution_checks: Arc<std::sync::atomic::AtomicU64>,
    /// L8 reconciliations that found a BLOCKED transaction executed on-chain:
    /// the gate was bypassed. The one number an operator must alert on.
    execution_discrepancies: Arc<std::sync::atomic::AtomicU64>,
    /// L8 reconciliations where the RPC returned transaction bytes that are
    /// not bound to the signature asked about (first slot differs, or the
    /// signature does not verify under the fee payer). An RPC that does this
    /// is faulty or hostile; the reconciliation is refused, not degraded.
    execution_chain_bytes_rejected: Arc<std::sync::atomic::AtomicU64>,
    /// L8 reconciliations where the primary RPC contradicted itself about a
    /// signature (slot or outcome differ between `getSignatureStatuses` and
    /// `getTransaction`) (Round 12).
    execution_chain_inconsistent: Arc<std::sync::atomic::AtomicU64>,
    /// L8 reconciliations where the inclusion witness disagreed with the
    /// primary RPC, or could not be consulted (Round 12).
    execution_witness_disagreements: Arc<std::sync::atomic::AtomicU64>,
    /// Lifecycle reports that sat wrongly against the rows already on
    /// record for their transaction: a duplicate, an out-of-order or
    /// unpreceded stage, or a conflicting signature (Round 12).
    lifecycle_sequence_anomalies: Arc<std::sync::atomic::AtomicU64>,
}

impl Metrics {
    fn inc(counter: &Arc<std::sync::atomic::AtomicU64>) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Per-IP token bucket (GCRA-style). Shared across clones via Arc.
///
/// The bucket map is BOUNDED at `MAX_BUCKETS` distinct IPs. When at capacity
/// the OLDEST-INSERTED bucket is evicted via a FIFO ring — O(1) amortized, so
/// an attacker rotating (spoofed, when behind a trusted proxy) IPs can never
/// trigger an O(n) full-map sweep. The previous implementation swept the
/// entire bucket map on every request at capacity, which was itself a CPU-DoS
/// vector at the exact layer meant to prevent DoS.
///
/// Tradeoff (recorded per Constitution P14): FIFO eviction means a client can
/// re-enter with a fresh bucket once MAX_BUCKETS distinct IPs have appeared.
/// At that scale per-IP limiting has already lost meaning, and bounding memory
/// is the priority.
#[derive(Clone)]
struct RateLimiter {
    buckets: Arc<Mutex<RateLimiterInner>>,
    per_second: f64,
    max_buckets: usize,
}

struct RateLimiterInner {
    buckets: HashMap<IpAddr, Bucket>,
    /// Insertion order, used as the FIFO eviction ring (bounded by MAX_BUCKETS).
    order: std::collections::VecDeque<IpAddr>,
}

const MAX_BUCKETS: usize = 1_000_000;

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(per_second: f64) -> Self {
        Self::with_capacity(MAX_BUCKETS, per_second)
    }

    /// Constructor with an explicit bucket cap (the production default is
    /// `MAX_BUCKETS`; small caps are used in tests to exercise FIFO eviction).
    fn with_capacity(max_buckets: usize, per_second: f64) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                order: std::collections::VecDeque::new(),
            })),
            per_second: per_second.max(0.1),
            max_buckets: max_buckets.max(1),
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut inner = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        // Bounded map: evict the oldest-inserted IP when a NEW IP arrives at
        // capacity. The while-loop amortizes to O(1): each pop_front removes
        // one entry from the ring even when the corresponding bucket was
        // already gone.
        if !inner.buckets.contains_key(&ip) && inner.buckets.len() >= self.max_buckets {
            while let Some(oldest) = inner.order.pop_front() {
                if inner.buckets.remove(&oldest).is_some() {
                    break;
                }
            }
        }

        // All map/ring mutations happen BEFORE the entry borrow, so the
        // HashMap entry never conflicts with the FIFO ring's borrow.
        let is_new = !inner.buckets.contains_key(&ip);
        if is_new {
            inner.order.push_back(ip);
        }
        // The bucket holds at least one whole token (Round 19, F-19-16): at a
        // configured rate below 1 req/s a bucket capped at `per_second` never
        // reached 1.0 and every request was refused. The rate is still the
        // refill; only the burst has a floor.
        let capacity = self.per_second.max(1.0);
        let bucket = inner.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Constant-time string comparison (prevents timing-based API-key probing).
///
/// Both inputs are hashed to fixed 32-byte SHA-256 digests BEFORE comparison
/// so the LENGTH of the expected key is never leaked: an early `len != len`
/// return (the previous implementation) let a remote attacker measure key
/// length through response timing. Comparing only the digests runs in
/// constant time regardless of input length.
fn ct_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());
    da.iter()
        .zip(db.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// The key a client is rate-limited under (Round 19, F-19-16).
///
/// An IPv6 client is limited per /64, not per address: a single host is
/// routinely handed a whole /64, so keying on the full address gave one
/// client 2^64 fresh buckets — the limit did not apply, and the bucket map
/// churned at its cap. IPv4 (and IPv4-mapped IPv6) is limited per address.
fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Best-effort client IP for per-IP rate limiting. `X-Forwarded-For` is
/// honored ONLY when the server is explicitly behind a trusted proxy
/// (`GRAPHITE_TRUST_PROXY`); otherwise the header is ignored entirely, so an
/// attacker who can reach the server directly cannot spoof it to rotate IPs
/// and bypass the limiter.
///
/// SECURITY (HIGH, 2026-09-05 production audit): this used to take the
/// LEFTMOST `X-Forwarded-For` entry, which is exactly the attacker-controlled
/// one. Every standard reverse proxy (nginx's `proxy_add_x_forwarded_for`,
/// Envoy, HAProxy, most CDNs) APPENDS the peer it actually observed to
/// whatever the client already sent, producing
/// `<client-supplied…>, <real client IP>`. Reading the left end therefore
/// read the client's own claim: an attacker set
/// `X-Forwarded-For: <random ip>` per request, got a fresh token bucket every
/// time, and the per-IP limit became a no-op — while a victim could also be
/// pinned to an attacker-chosen bucket.
///
/// The trustworthy entry is counted from the RIGHT: with `hops` trusted
/// proxies in front, the last `hops` entries were appended by infrastructure
/// under the operator's control, and the real client IP is the leftmost of
/// THOSE. Anything further left is caller-supplied and must never be
/// believed.
///
/// A request with no `X-Forwarded-For` at all is keyed by its direct peer: a
/// client reaching the server directly, or the proxy's own traffic. A request
/// that carries the header but whose chain cannot name a client — fewer
/// entries than the configured hop count (it did not traverse the expected
/// chain), or a malformed entry at the client's position — is keyed by
/// [`UNATTRIBUTED_CLIENT`], never by a chain entry it does not trust (P12).
fn client_ip(
    req: &axum::http::Request<axum::body::Body>,
    addr: SocketAddr,
    trust_proxy_hops: u8,
) -> IpAddr {
    if trust_proxy_hops == 0 {
        return addr.ip();
    }
    // EVERY `X-Forwarded-For` line, in order (A4-02, 2026-09-29 audit).
    // HTTP defines repeated header lines as one comma-joined list, and a
    // proxy that appends its entry as a NEW line leaves the client's own line
    // first. Reading only the first line read the client's claim: a second
    // line chose the rate-limit bucket.
    //
    // Read as BYTES (audit 2026-10-20, L1). A line that was not visible ASCII
    // made the whole chain untrusted and fell back to the peer address — the
    // proxy's, behind `GRAPHITE_TRUST_PROXY` — so one byte >= 0x80 in the
    // client's OWN line moved its requests into the bucket every client
    // behind the proxy falls back to, and draining it cost nothing. Only the
    // entry at the client's position must parse; the client-supplied entries
    // to its left are never read, whatever they contain. A comma is ASCII, so
    // splitting on it cannot be confused by any other byte.
    let mut present = false;
    let mut entries: Vec<&[u8]> = Vec::new();
    for v in req.headers().get_all("x-forwarded-for") {
        present = true;
        entries.extend(
            v.as_bytes()
                .split(|b| *b == b',')
                .map(<[u8]>::trim_ascii)
                .filter(|e| !e.is_empty()),
        );
    }
    if !present {
        return addr.ip();
    }
    // Index from the right by the number of proxies we actually trust.
    // `entries.len() < hops` means the request did not come through the full
    // expected chain — do not trust any of it.
    let hops = trust_proxy_hops as usize;
    if entries.len() < hops {
        return UNATTRIBUTED_CLIENT;
    }
    forwarded_entry_ip(entries[entries.len() - hops]).unwrap_or(UNATTRIBUTED_CLIENT)
}

/// The rate-limit key of a request whose forwarded chain cannot name its
/// client (audit 2026-10-20, L1).
///
/// Not the peer address: behind a trusted proxy the peer is the proxy, and
/// its bucket is the one the proxy's own requests use, so a client that
/// could steer its requests there could exhaust it at will. Not a fresh key
/// per request either: that would be a way around the limiter. One shared
/// bucket, then, that only unattributable requests reach. With the hop count
/// right every proxied request carries a parseable entry at the client's
/// position (the proxy wrote it), so in a correct deployment this bucket is
/// empty; when it is not, the requests in it share one rate, and exhausting
/// it costs only other unattributable requests. `0100::` is the IPv6
/// discard-only prefix (RFC 6666): no peer ever has this address, and
/// `rate_limit_key`'s /64 masking leaves it as it is.
const UNATTRIBUTED_CLIENT: IpAddr =
    IpAddr::V6(std::net::Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0));

/// One `X-Forwarded-For` entry as a client address. An entry may carry a
/// port (`203.0.113.7:4711`, `[2001:db8::1]:443` — some proxies write one); it
/// names the same client, so it keys the same bucket.
fn forwarded_entry_ip(entry: &[u8]) -> Option<IpAddr> {
    let v = std::str::from_utf8(entry).ok()?;
    v.parse::<IpAddr>()
        .ok()
        .or_else(|| v.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

pub use crate::verification::{lock_data_dir, DATA_DIR_LOCK};

/// Verify the data directory is actually WRITABLE, not merely present.
///
/// DURABILITY (CRITICAL, 2026-09-05 deployment audit): the standard container
/// failure is a Docker named volume mounted at `/data` that the engine
/// creates `root:root 0755` while the container process runs as an
/// unprivileged user. `create_dir_all` then SUCCEEDS (the directory exists),
/// the server starts, `/health` returns 200 — and every audit-log append and
/// semantic-graph snapshot silently fails for the lifetime of the deployment.
/// The operator sees a healthy service that is quietly not recording anything.
///
/// An unwritable data directory is an internal integrity failure, not
/// protocol uncertainty: Graphite cannot satisfy P9 (immutable audit trail
/// for every lifecycle event) or persist earned trust state. Per the
/// Constitution's Error Response framework that is a "stop, don't serve"
/// condition (response 5), not a degrade-and-continue one — so this returns
/// an error and the server refuses to start, loudly, with a message naming
/// the likely cause.
fn probe_data_dir_writable(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let probe = dir.join(".graphite-write-probe");
    match std::fs::write(&probe, b"graphite") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!(
            "data directory {} is not writable: {e}. Graphite refuses to start without a \
             durable audit trail (Constitution P9). If running in a container, ensure the \
             volume mounted here is owned by the container's user \
             (e.g. `mkdir -p /data && chown <uid>:<gid> /data` in the image, or \
             `user: \"<uid>:<gid>\"` in compose).",
            dir.display()
        )
        .into()),
    }
}

/// Install the global tracing subscriber.
///
/// OBSERVABILITY (2026-09-05 production audit): the crate emits
/// `tracing::info!/warn!/error!` throughout — including audit-log write
/// failures in `durable.rs` and RPC failures in `rpc_client.rs` — but no
/// subscriber was ever installed, so every one of those calls was a silent
/// no-op. An operator whose disk filled up got NO signal that the append-only
/// audit trail (P9) had stopped being written.
///
/// `GRAPHITE_LOG_FORMAT=json` emits structured JSON (the enterprise/log-
/// aggregator default); anything else emits human-readable text. Level is
/// controlled by `RUST_LOG` (default `info`). Idempotent: a second call is a
/// no-op rather than a panic, so embedding callers and tests that install
/// their own subscriber are unaffected.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("GRAPHITE_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    // `try_init` returns Err if a subscriber is already set — that is a
    // legitimate state (embedded use, tests), not a failure.
    let _ = if json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_current_span(false)
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    };
}

/// How the server will authenticate, decided from the environment BEFORE
/// anything binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPosture {
    /// Every route except `/health` requires the Bearer key.
    ApiKey(Arc<String>),
    /// No authentication. Reachable only because the operator set
    /// `GRAPHITE_DEV_MODE=1` explicitly AND the bind address is loopback.
    DevModeLoopback,
}

/// Environment variable that permits an unauthenticated instance.
pub const DEV_MODE_ENV: &str = "GRAPHITE_DEV_MODE";

/// The shortest `GRAPHITE_API_KEY` the server will start with (Round 11).
///
/// The key is the only thing between the network and `/verify`, and the
/// comparison is constant-time, so its strength is its length. 32 characters
/// is what `openssl rand -hex 16` produces — 128 bits — and half of what the
/// documentation recommends. A five-character key is a guessable key, and a
/// gate that starts with one is not fail-closed.
pub const MIN_API_KEY_CHARS: usize = 32;

/// Decide the auth posture, refusing every combination that used to start.
///
/// Default = authenticated. Until 2026-09-12 the default was the other way
/// round: an absent `GRAPHITE_API_KEY` meant "dev mode" and the server
/// started unauthenticated, with only the CLI's loopback guard between a
/// forgotten variable and a network-reachable gate. A security gate whose
/// safe configuration is the one you have to remember to set is not
/// fail-closed. Now an absent key is a startup error unless
/// `GRAPHITE_DEV_MODE=1` is set — a deliberate act with a name that says what
/// it does — and even then only on a loopback address.
///
/// `api_key` is the raw environment value (whitespace-only counts as unset);
/// `dev_mode` is whether `GRAPHITE_DEV_MODE` is `1` or `true`.
pub fn auth_posture(
    addr: SocketAddr,
    api_key: Option<&str>,
    dev_mode: bool,
) -> Result<AuthPosture, String> {
    if let Some(key) = api_key.map(str::trim).filter(|k| !k.is_empty()) {
        let chars = key.chars().count();
        if chars < MIN_API_KEY_CHARS {
            return Err(format!(
                "refusing to start: GRAPHITE_API_KEY is {chars} characters; at least \
                 {MIN_API_KEY_CHARS} are required. Generate one with `openssl rand -hex 32`."
            ));
        }
        return Ok(AuthPosture::ApiKey(Arc::new(key.to_string())));
    }
    if !dev_mode {
        return Err(format!(
            "refusing to start without GRAPHITE_API_KEY. Every route except /health \
             requires a Bearer key; generate one with `openssl rand -hex 32`. To run an \
             UNAUTHENTICATED instance for local development, set {DEV_MODE_ENV}=1 — it \
             is then permitted only on a loopback address."
        ));
    }
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind {addr} unauthenticated: {DEV_MODE_ENV} permits a keyless \
             instance only on a loopback address (127.0.0.1 / ::1). Set GRAPHITE_API_KEY \
             to bind a reachable address."
        ));
    }
    Ok(AuthPosture::DevModeLoopback)
}

/// The operator key from `GRAPHITE_ADMIN_API_KEY` (Round 19, F-19-13).
///
/// Optional: without it the `/admin/*` surface is disabled. When set it must
/// be as long as a verify key and must NOT equal it — an operator key that is
/// the verify key is no separation at all, and a server that accepted it
/// would report a posture it does not have.
pub fn operator_key_posture(
    admin_key: Option<&str>,
    api_key: Option<&str>,
) -> Result<Option<Arc<String>>, String> {
    let Some(admin) = admin_key.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    let chars = admin.chars().count();
    if chars < MIN_API_KEY_CHARS {
        return Err(format!(
            "refusing to start: GRAPHITE_ADMIN_API_KEY is {chars} characters; at least \
             {MIN_API_KEY_CHARS} are required. Generate one with `openssl rand -hex 32`."
        ));
    }
    if api_key.map(str::trim) == Some(admin) {
        return Err(
            "refusing to start: GRAPHITE_ADMIN_API_KEY equals GRAPHITE_API_KEY. The operator key \
             must be a different secret from the key agents verify with, or the operator surface \
             is open to every agent."
                .to_string(),
        );
    }
    Ok(Some(Arc::new(admin.to_string())))
}

/// `GRAPHITE_READ_API_KEY` (Round 30, K-11): the read-only scope. Unset or
/// empty is none. Held to the verify key's length rule, and refused when it
/// equals either other key — a read key that is also the verify key is no
/// narrower than it. With no verify key (dev mode) every route is already
/// open on loopback, and a read key would suggest a boundary that does not
/// exist, so it refuses to start.
pub fn read_key_posture(
    read_key: Option<&str>,
    api_key: Option<&str>,
    admin_key: Option<&str>,
) -> Result<Option<Arc<String>>, String> {
    let Some(read) = read_key.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    if api_key.is_none() {
        return Err(
            "refusing to start: GRAPHITE_READ_API_KEY is set without GRAPHITE_API_KEY; an \
             unauthenticated (dev-mode) server has no scopes to narrow"
                .to_string(),
        );
    }
    let chars = read.chars().count();
    if chars < MIN_API_KEY_CHARS {
        return Err(format!(
            "refusing to start: GRAPHITE_READ_API_KEY is {chars} characters; at least \
             {MIN_API_KEY_CHARS} are required. Generate one with `openssl rand -hex 32`."
        ));
    }
    if api_key.map(str::trim) == Some(read) || admin_key.map(str::trim) == Some(read) {
        return Err(
            "refusing to start: GRAPHITE_READ_API_KEY equals GRAPHITE_API_KEY or \
             GRAPHITE_ADMIN_API_KEY. The read key must be its own secret, or it opens more \
             than reads."
                .to_string(),
        );
    }
    Ok(Some(Arc::new(read.to_string())))
}

/// The routes the read key opens (Round 30, K-11): every `GET` that only
/// reports. `/health` needs no key; `/admin/*` needs the operator key; every
/// `POST` verifies or records and needs the verify key.
fn is_read_route(method: &Method, route: &str) -> bool {
    method == Method::GET
        && (route == "/metrics" || route == "/manifests" || route.starts_with("/api/"))
}

/// Why `GRAPHITE_L8_HIGH_ASSURANCE=1` cannot be honoured with this
/// configuration, or `None` when it can (Round 30, G-08).
///
/// High assurance means no L8 conclusion about the chain rests on one
/// provider. That needs: a primary and a witness (`independence` is `None`
/// without both); the witness judged a distinct host, domain and address;
/// both reached over https, since plaintext answers can be rewritten in
/// transit; and the operator's attestation of the two providers' names
/// (`GRAPHITE_RPC_PROVIDER`, `GRAPHITE_RPC_WITNESS_PROVIDER`), different from
/// each other — two hostnames can belong to one company, and only the
/// operator knows whose they are.
fn high_assurance_refusal(
    independence: Option<&crate::rpc_client::WitnessIndependence>,
    providers: (Option<&str>, Option<&str>),
    schemes: (Option<&str>, Option<&str>),
) -> Option<String> {
    let Some(independence) = independence else {
        return Some(
            "it needs GRAPHITE_RPC_URL and an inclusion witness, GRAPHITE_RPC_WITNESS_URL".into(),
        );
    };
    if let crate::rpc_client::WitnessIndependence::NotIndependent(why) = independence {
        return Some(format!(
            "the inclusion witness is not an independent provider ({why})"
        ));
    }
    if schemes.0 != Some("https") || schemes.1 != Some("https") {
        return Some(
            "the primary RPC and the witness must both be https; a plaintext answer can be rewritten in transit".into(),
        );
    }
    let name = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
    };
    match (name(providers.0), name(providers.1)) {
        (Some(p), Some(w)) if p != w => None,
        (Some(_), Some(_)) => Some(
            "GRAPHITE_RPC_PROVIDER and GRAPHITE_RPC_WITNESS_PROVIDER name the same provider".into(),
        ),
        _ => Some(
            "it needs the operator to name both providers: GRAPHITE_RPC_PROVIDER and GRAPHITE_RPC_WITNESS_PROVIDER".into(),
        ),
    }
}

/// Whether `GRAPHITE_DEV_MODE` is set to an affirmative value.
pub fn dev_mode_from_env() -> bool {
    std::env::var(DEV_MODE_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// `GRAPHITE_QUARANTINE_ON_UPGRADE` (roadmap R-M1): unset, empty, `0` or
/// `false` is off; `1` or `true` is on; anything else refuses to start, so a
/// typo is never a silent "off". The rule every boolean switch now follows
/// (`boundary::env_flag`).
#[cfg(test)]
fn quarantine_on_upgrade_from(value: Option<&str>) -> Result<bool, String> {
    env_flag("GRAPHITE_QUARANTINE_ON_UPGRADE", value)
}

/// `GRAPHITE_TRUST_PROXY`: the number of trusted proxy hops in front of this
/// server (`1` = the common single reverse-proxy/LB setup). `true` is a
/// compatibility alias for `1`, `false` for `0`; unset or empty is 0.
///
/// Anything else refuses to start (audit 2026-10-20): it used to read as 0,
/// so `GRAPHITE_TRUST_PROXY=yes` started a server that put every client
/// behind the proxy in the proxy's one rate-limit bucket, with nothing said.
fn trust_proxy_hops_from(value: Option<&str>) -> Result<u8, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(0),
        Some(v) if v.eq_ignore_ascii_case("true") => Ok(1),
        Some(v) if v.eq_ignore_ascii_case("false") => Ok(0),
        Some(v) => v.parse::<u8>().map_err(|_| {
            format!(
                "invalid GRAPHITE_TRUST_PROXY {v:?}: must be the number of trusted proxy hops (0-255), or true (= 1) / false (= 0). REFUSING TO START."
            )
        }),
    }
}

/// `GRAPHITE_CORS_ORIGINS`: a comma-separated list of browser origins
/// allowed to call the API, each `http://` or `https://` plus a host and
/// optional port, nothing after it.
///
/// A wildcard is refused (audit 2026-10-20, L2): `*` reached tower-http's
/// origin list, which panics on it, so the server died at startup with a
/// backtrace instead of a configuration error. It is refused rather than
/// honoured because the API is credentialed — every route but `/health`
/// takes the Bearer key — and a wildcard would let any page a key-holder's
/// browser visits drive the API with a key it obtained. An entry that is not
/// an origin (a path, a trailing slash, whitespace inside) used to be dropped
/// silently or kept unmatchable; it is refused too.
fn cors_origins_from(value: Option<&str>) -> Result<Vec<HeaderValue>, String> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut origins = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return Err(
                "GRAPHITE_CORS_ORIGINS=* is refused: the API is credentialed (Bearer key), and a wildcard origin would let any web page drive it. List the dashboard's origins explicitly, e.g. https://dashboard.example.com. REFUSING TO START."
                    .to_string(),
            );
        }
        let rest = entry
            .strip_prefix("https://")
            .or_else(|| entry.strip_prefix("http://"));
        let is_origin = rest.is_some_and(|host| {
            !host.is_empty()
                && !host.contains(['/', '?', '#', '*'])
                && !host.chars().any(char::is_whitespace)
        });
        if !is_origin {
            return Err(format!(
                "GRAPHITE_CORS_ORIGINS entry {entry:?} is not an origin (scheme://host[:port], http or https, nothing after it). REFUSING TO START."
            ));
        }
        origins.push(HeaderValue::from_str(entry).map_err(|_| {
            format!("GRAPHITE_CORS_ORIGINS entry {entry:?} is not a valid header value. REFUSING TO START.")
        })?);
    }
    Ok(origins)
}

/// The server's numeric limits, read strictly from `get` (audit 2026-10-20:
/// each fell back to its default on a value that did not parse, so a typo'd
/// limit ran with a number nobody chose, while `GRAPHITE_RATE_LIMIT` beside
/// them refused to start).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    rotate_bytes: u64,
    max_archives: usize,
    inflight_limit: usize,
    max_connections: usize,
    max_per_peer: usize,
    connection_lifetime: Duration,
}

impl Limits {
    fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        trust_proxy_hops: u8,
    ) -> Result<Self, String> {
        let var = |name: &str| get(name);
        Ok(Self {
            rotate_bytes: env_number(
                "GRAPHITE_AUDIT_ROTATE_BYTES",
                var("GRAPHITE_AUDIT_ROTATE_BYTES").as_deref(),
                crate::durable::DEFAULT_ROTATE_BYTES,
                "a whole number of bytes (0 disables rotation)",
                |_| true,
            )?,
            max_archives: env_number(
                "GRAPHITE_AUDIT_MAX_ARCHIVES",
                var("GRAPHITE_AUDIT_MAX_ARCHIVES").as_deref(),
                0usize,
                "a whole number of archives (0 keeps every archive)",
                |_| true,
            )?,
            inflight_limit: env_number(
                "GRAPHITE_MAX_CONCURRENT",
                var("GRAPHITE_MAX_CONCURRENT").as_deref(),
                DEFAULT_MAX_CONCURRENT_VERIFICATIONS,
                "a whole number of verifications greater than 0",
                |n| n > 0,
            )?,
            max_connections: env_number(
                "GRAPHITE_MAX_CONNECTIONS",
                var("GRAPHITE_MAX_CONNECTIONS").as_deref(),
                DEFAULT_MAX_CONNECTIONS,
                "a whole number of connections greater than 0",
                |n| n > 0,
            )?,
            // Behind a trusted proxy every connection comes from the proxy,
            // so the default there is no per-peer cap.
            max_per_peer: env_number(
                "GRAPHITE_MAX_CONNECTIONS_PER_IP",
                var("GRAPHITE_MAX_CONNECTIONS_PER_IP").as_deref(),
                if trust_proxy_hops == 0 {
                    DEFAULT_MAX_CONNECTIONS_PER_PEER
                } else {
                    0
                },
                "a whole number of connections (0 = no per-peer cap)",
                |_| true,
            )?,
            connection_lifetime: Duration::from_secs(env_number(
                "GRAPHITE_CONNECTION_LIFETIME_SECS",
                var("GRAPHITE_CONNECTION_LIFETIME_SECS").as_deref(),
                DEFAULT_CONNECTION_LIFETIME.as_secs(),
                "a whole number of seconds greater than 0",
                |n| n > 0,
            )?),
        })
    }
}

pub async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    // Decided first, before the data directory is touched or anything binds,
    // so a misconfigured deployment fails at the first line of output rather
    // than after it has already started serving.
    let posture = auth_posture(
        addr,
        std::env::var("GRAPHITE_API_KEY").ok().as_deref(),
        dev_mode_from_env(),
    )?;

    // ---- configuration from environment ----
    let data_dir = std::env::var("GRAPHITE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("graphite-data"));
    std::fs::create_dir_all(&data_dir)?;
    // Creating the directory is not the same as being able to WRITE in it:
    // the common container failure is a volume mounted root-owned while the
    // process runs unprivileged, where `create_dir_all` succeeds (the dir
    // already exists) and every subsequent audit append fails. Durability of
    // the audit trail is a P9 guarantee, not a nice-to-have, so probe it now
    // and refuse to start rather than serve traffic with no audit trail.
    probe_data_dir_writable(&data_dir)?;
    // Takes the directory's lock (held by the core for the life of the
    // process) and refuses a corrupt snapshot. See `GraphiteCore::open_data_dir`.
    let mut core = GraphiteCore::open_data_dir(data_dir.clone())?;
    // A simulation observation trains the baseline only once its verdict is
    // on the audit trail (W21): see `verify_handler`.
    core.defer_observations_until_recorded();

    // The operator's boundary policy — the pinned wallet profile, the
    // permissive-profile opt-out, durable nonces, the upgrade quarantine and
    // the plugins directory — read by the same code `graphite verify` reads
    // it with (audit 2026-10-20, L11), so the CLI reproduces this server's
    // decision. Every switch is read strictly: a value other than
    // 1/true/0/false is a startup error, never a silent "off".
    let policy = OperatorPolicy::from_env()?;

    // Durable-nonce transactions: refused at L2 unless the operator opts in,
    // and then only after the nonce account is verified on-chain. See
    // `GraphiteCore::set_allow_durable_nonce`. Roadmap R-M1: a program
    // redeployed since Graphite last saw it is always reported; quarantining
    // it as well is the operator's decision.
    //
    // Plugin framework (Constitution P8): approved third-party plugin
    // manifests from GRAPHITE_PLUGINS_DIR are activated (review gate —
    // pending/rejected manifests are skipped). Round 17 (F-16-07): an
    // operator who configured a plugin directory expects those plugins to be
    // running, so one that does not load is a startup error.
    let plugins = policy.apply_to_core(&mut core)?;
    if policy.quarantine_on_upgrade {
        tracing_log(
            "a program redeployed since Graphite last saw it is QUARANTINED until the operator lifts it (GRAPHITE_QUARANTINE_ON_UPGRADE=1)",
        );
    }
    if policy.allow_durable_nonce {
        tracing_log(
            "durable-nonce transactions PERMITTED (GRAPHITE_ALLOW_DURABLE_NONCE=1): they do not expire; each one is verified against its nonce account on-chain before L2 passes",
        );
    }
    // Round 32: the production defaults refuse these; an operator who
    // relaxes one is told so at every start.
    if policy.allow_unreadable_value_declarations {
        tracing_log(
            "L4 RELAXED (GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS=1): a signer's loss under a declaration Graphite cannot read only WARNS when the instruction's class moves value",
        );
    }
    if policy.allow_signer_lamports_outside_declared_debit {
        tracing_log(
            "L4 RELAXED (GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT=1): lamports leaving a signer's wallet under a debit declared for other accounts only WARN",
        );
    }
    if policy.allow_unbounded_withdrawals {
        tracing_log(
            "grants RELAXED (GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1): a granted withdrawal whose every minimum output is zero is not refused",
        );
    }
    if let (Some(summary), Some(dir)) = (plugins, &policy.plugins_dir) {
        // Round 19 (F-19-26): say what "skipped" means. A manifest is the
        // review gate for activating a plugin from this directory; the
        // reviewed, in-tree built-ins are registered by the core itself and
        // stay active whatever a manifest here says about them — a file in a
        // directory must not be able to switch off a check. The log used to
        // read as though a rejected manifest had disabled one.
        tracing_log(&format!(
            "plugins: {} registered, {} pending (not activated), {} rejected (not activated), {} already registered (not run again) from {}; the built-in plugins are always active and are not governed by manifests in this directory",
            summary.registered,
            summary.skipped_pending,
            summary.skipped_rejected,
            summary.already_registered,
            dir.display()
        ));
    }
    // Optionally mirror every verification event to a JSON-lines file for
    // production observability. A file the operator named that cannot be
    // attached is a startup error (audit 2026-10-20), as an unloadable
    // GRAPHITE_PLUGINS_DIR is: it used to log one line and start without
    // it, so the stream the operator's tooling reads was silently absent.
    if let Ok(events_file) = std::env::var("GRAPHITE_PLUGIN_EVENTS_FILE") {
        if !events_file.trim().is_empty() {
            // The sink opens its file lazily, on the first event, so attaching
            // proves nothing about the path: it is opened for append here, as
            // the sink will, so a path that cannot be written refuses to start.
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&events_file)
                .map_err(|e| {
                    format!(
                        "plugins: FAILED to open the event file {events_file} (GRAPHITE_PLUGIN_EVENTS_FILE): {e} — refusing to start without the event stream the operator configured"
                    )
                })?;
            core.attach_event_file_sink(std::path::Path::new(&events_file))
                .map_err(|e| {
                    format!(
                        "plugins: FAILED to attach the event file {events_file} (GRAPHITE_PLUGIN_EVENTS_FILE): {e} — refusing to start without the event stream the operator configured"
                    )
                })?;
            tracing_log(&format!(
                "plugins: verification events appended to {}",
                events_file
            ));
        }
    }

    // The endpoints are validated before a client is built on them. An
    // unusable URL used to start the server with "live L3/L4 enabled" in
    // the log and every simulation Inconclusive (Round 12). Nothing about
    // the URL beyond its scheme and whether it is loopback is logged: a
    // managed provider's URL carries the operator's key.
    let rpc_facts = |name: &str,
                     endpoint: &str|
     -> Result<crate::rpc_client::EndpointFacts, String> {
        let facts = crate::rpc_client::validate_endpoint(endpoint)
            .map_err(|e| format!("{name} is unusable: {e}"))?;
        if facts.scheme == "http" && !facts.loopback {
            tracing_log(&format!(
                "WARNING: {name} is plaintext http to a non-loopback host; every RPC answer L3/L4/L8 rely on can be altered in transit. Use https, or a loopback proxy that terminates TLS"
            ));
        }
        if facts.has_userinfo {
            tracing_log(&format!(
                "{name} carries credentials in the URL; they are never logged"
            ));
        }
        if facts.private_network {
            tracing_log(&format!(
                "{name} is a private-network address (RFC 1918 / CGNAT / unique-local); allowed, and said so in case it points inside the network by mistake"
            ));
        }
        Ok(facts)
    };
    // High-assurance L8 (Round 30, G-08): read before any client is built so
    // a typo refuses to start rather than running at single-provider
    // assurance the operator did not choose.
    let l8_high_assurance = crate::operator_boundary::env_flag(
        "GRAPHITE_L8_HIGH_ASSURANCE",
        std::env::var("GRAPHITE_L8_HIGH_ASSURANCE").ok().as_deref(),
    )?;
    if let Ok(endpoint) = std::env::var("GRAPHITE_RPC_URL") {
        if !endpoint.is_empty() {
            let facts = rpc_facts("GRAPHITE_RPC_URL", &endpoint)?;
            // The RPC budget has to fit INSIDE the request timeout, and until
            // 2026-09-08 it did not: this used `RpcConfig::default()`, a
            // 30-second per-call timeout with 3 retries, behind a 10-second
            // REQUEST_TIMEOUT. A verification makes up to three calls, so the
            // worst case was minutes of RPC work behind a ten-second deadline —
            // and the deadline always won, returning a bare 408 with no verdict
            // and writing nothing to the audit trail. See `RpcBudget`.
            //
            // Per-call timeout and retries are sized so a single stalled call
            // cannot consume the whole budget; the shared deadline inside the
            // pipeline is what enforces the total.
            const PER_CALL: Duration = Duration::from_secs(3);
            const RETRIES: u32 = 1;
            // A compile-time statement of the relationship the two constants
            // have to keep. If someone raises the RPC budget or lowers the
            // request timeout, this stops the build instead of quietly
            // recreating the inverted-timeout bug.
            const _: () = assert!(
                BODY_READ_TIMEOUT.as_secs() + crate::verification::DEFAULT_RPC_BUDGET.as_secs() + 2
                    <= REQUEST_TIMEOUT.as_secs(),
                "the body read and the RPC budget must leave headroom inside REQUEST_TIMEOUT for the rest of the pipeline"
            );
            let client = crate::rpc_client::SolanaRpcClient::new(crate::rpc_client::RpcConfig {
                endpoint,
                timeout: PER_CALL,
                max_retries: RETRIES,
                ..Default::default()
            });
            core.attach_rpc_client(client);
            core.set_rpc_budget(crate::verification::DEFAULT_RPC_BUDGET);
            tracing_log(&format!(
                "RPC client attached — live L3/L4 enabled (GRAPHITE_RPC_URL, {}{}); per-call timeout {}s, {} retry, total budget {}s inside a {}s request timeout; redirects not followed",
                facts.scheme,
                if facts.loopback { ", loopback" } else { "" },
                PER_CALL.as_secs(),
                RETRIES,
                crate::verification::DEFAULT_RPC_BUDGET.as_secs(),
                REQUEST_TIMEOUT.as_secs()
            ));

            // A second, independent RPC for L8's inclusion question
            // (Round 12). Optional; without it L8 says so in every
            // reconciliation's `inclusion_witness: null`.
            if let Ok(witness) = std::env::var("GRAPHITE_RPC_WITNESS_URL") {
                if !witness.is_empty() {
                    let wfacts = rpc_facts("GRAPHITE_RPC_WITNESS_URL", &witness)?;
                    // Is the witness another provider (Round 30, G-08)? The
                    // URLs first, then the addresses they resolve to. A
                    // check that cannot run is not a pass: without
                    // high-assurance it falls back to the URL judgement and
                    // says so; with it, the server does not start.
                    let primary_endpoint = std::env::var("GRAPHITE_RPC_URL").unwrap_or_default();
                    let independence = match crate::rpc_client::witness_independence_resolved(
                        &primary_endpoint,
                        &witness,
                    )
                    .await
                    {
                        Ok(i) => i,
                        Err(why) if l8_high_assurance => {
                            return Err(format!(
                                "GRAPHITE_L8_HIGH_ASSURANCE=1 needs the witness's independence checked, and it could not be: {why}. REFUSING TO START."
                            )
                            .into())
                        }
                        Err(why) => {
                            tracing_log(&format!(
                                "inclusion witness: the address check could not run ({why}); independence judged from the URLs alone"
                            ));
                            crate::rpc_client::witness_independence(&primary_endpoint, &witness)
                        }
                    };
                    let client =
                        crate::rpc_client::SolanaRpcClient::new(crate::rpc_client::RpcConfig {
                            endpoint: witness,
                            timeout: PER_CALL,
                            max_retries: RETRIES,
                            ..Default::default()
                        });
                    core.attach_inclusion_witness(client)
                        .map_err(|e| format!("GRAPHITE_RPC_WITNESS_URL: {e}"))?;
                    core.set_witness_independence(independence.clone());
                    tracing_log(&format!(
                        "inclusion witness attached — L8 asks a second RPC about every signature (GRAPHITE_RPC_WITNESS_URL, {}{}); {}",
                        wfacts.scheme,
                        if wfacts.loopback { ", loopback" } else { "" },
                        match &independence {
                            crate::rpc_client::WitnessIndependence::Distinct =>
                                "a distinct host, domain and address from the primary".to_string(),
                            crate::rpc_client::WitnessIndependence::NotIndependent(why) => format!(
                                "NOT an independent provider ({why}): its agreement is reported as witnessed_not_independent"
                            ),
                        }
                    ));
                }
            }
        } else if std::env::var("GRAPHITE_RPC_WITNESS_URL").is_ok_and(|w| !w.is_empty()) {
            return Err(
                "GRAPHITE_RPC_WITNESS_URL is set but GRAPHITE_RPC_URL is not; a witness needs a primary to witness"
                    .into(),
            );
        }
    } else if std::env::var("GRAPHITE_RPC_WITNESS_URL").is_ok_and(|w| !w.is_empty()) {
        return Err(
            "GRAPHITE_RPC_WITNESS_URL is set but GRAPHITE_RPC_URL is not; a witness needs a primary to witness"
                .into(),
        );
    }

    if l8_high_assurance {
        let names = (
            std::env::var("GRAPHITE_RPC_PROVIDER").ok(),
            std::env::var("GRAPHITE_RPC_WITNESS_PROVIDER").ok(),
        );
        let schemes = (
            std::env::var("GRAPHITE_RPC_URL")
                .ok()
                .and_then(|u| crate::rpc_client::validate_endpoint(&u).ok())
                .map(|f| f.scheme),
            std::env::var("GRAPHITE_RPC_WITNESS_URL")
                .ok()
                .and_then(|u| crate::rpc_client::validate_endpoint(&u).ok())
                .map(|f| f.scheme),
        );
        if let Some(refusal) = high_assurance_refusal(
            core.witness_independence().as_ref(),
            (names.0.as_deref(), names.1.as_deref()),
            (schemes.0.as_deref(), schemes.1.as_deref()),
        ) {
            return Err(
                format!("GRAPHITE_L8_HIGH_ASSURANCE=1: {refusal}. REFUSING TO START.").into(),
            );
        }
        core.set_require_independent_witness(true);
        tracing_log(&format!(
            "high-assurance L8 (GRAPHITE_L8_HIGH_ASSURANCE=1): a statement of what the chain holds needs the independent witness to agree; providers attested by the operator as {:?} (primary) and {:?} (witness)",
            names.0.as_deref().map(str::trim).unwrap_or_default(),
            names.1.as_deref().map(str::trim).unwrap_or_default(),
        ));
    } else if core.has_inclusion_witness() {
        tracing_log(
            "L8 assurance: with the witness answering and agreeing, reconciliations read `witnessed`; one that is unreachable or disagrees withholds a positive conclusion (set GRAPHITE_L8_HIGH_ASSURANCE=1 to require it for every conclusion)",
        );
    } else if std::env::var("GRAPHITE_RPC_URL").is_ok_and(|u| !u.is_empty()) {
        tracing_log(
            "L8 assurance: single provider — without GRAPHITE_RPC_WITNESS_URL every L8 account of inclusion is the primary RPC's word, reported as `single_provider`",
        );
    }

    // Round 30 (G-01): without an RPC nothing is simulated, so no verdict
    // this node returns can permit signing. Said once, loudly, at start —
    // and on /health as `verification_mode` — so an operator who forgot
    // GRAPHITE_RPC_URL learns it from the log rather than from a caller.
    if !core.has_rpc_client() {
        tracing_server_error(
            "ANALYSIS-ONLY MODE: GRAPHITE_RPC_URL is not set, so no transaction is simulated and EVERY verdict is `decision: analysis_only` (`executable: false`) — approvals here are analysis, never permission to sign. Set GRAPHITE_RPC_URL for executable verdicts.",
        );
    }

    let api_key = match &posture {
        AuthPosture::ApiKey(key) => Some(key.clone()),
        AuthPosture::DevModeLoopback => None,
    };
    let admin_key = operator_key_posture(
        std::env::var("GRAPHITE_ADMIN_API_KEY").ok().as_deref(),
        api_key.as_deref().map(String::as_str),
    )?;
    let read_key = read_key_posture(
        std::env::var("GRAPHITE_READ_API_KEY").ok().as_deref(),
        api_key.as_deref().map(String::as_str),
        admin_key.as_deref().map(String::as_str),
    )?;
    if read_key.is_some() {
        tracing_log(
            "read key configured (GRAPHITE_READ_API_KEY): it opens /metrics, /manifests and /api/* and nothing else; give it to the dashboard instead of the verify key",
        );
    }

    // Round 17 (F-16-15): `inf` disabled the limiter and `NaN` collapsed it
    // to the 0.1 req/s floor. A non-finite or non-positive value is a
    // configuration error the operator must see.
    let rate_per_sec = match std::env::var("GRAPHITE_RATE_LIMIT") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<f64>() {
            Ok(n) if n.is_finite() && n > 0.0 => n,
            _ => {
                return Err(format!(
                    "invalid GRAPHITE_RATE_LIMIT {v:?}: must be a finite number of requests per second greater than 0"
                )
                .into())
            }
        },
        _ => 30.0,
    };

    let cors_origins = cors_origins_from(std::env::var("GRAPHITE_CORS_ORIGINS").ok().as_deref())?;

    // X-Forwarded-For is only honored behind an explicitly-trusted proxy.
    // The value is the NUMBER OF TRUSTED PROXY HOPS in front of this server.
    // See `client_ip` for why the count matters: entries are trusted from
    // the right, so an over-count would start believing caller-supplied
    // values again.
    let trust_proxy_hops =
        trust_proxy_hops_from(std::env::var("GRAPHITE_TRUST_PROXY").ok().as_deref())?;
    let limits = Limits::from_lookup(|k| std::env::var(k).ok(), trust_proxy_hops)?;

    // Audit log rotation bounds BOTH unbounded disk growth and the dashboard
    // endpoints' full-file scan cost. Archives are kept forever by default
    // (P9): pruning is opt-in via GRAPHITE_AUDIT_MAX_ARCHIVES, so discarding
    // audit history is always an explicit operator decision.
    let rotate_bytes = limits.rotate_bytes;
    let max_archives = limits.max_archives;
    if rotate_bytes == 0 {
        // Audit 2026-10-20: rotation off keeps one active file, and the
        // in-memory indexes over it (three keys per verification), for the
        // life of the process.
        tracing::warn!(
            "GRAPHITE_AUDIT_ROTATE_BYTES=0: the active audit file and its in-memory indexes grow without bound for the life of the process"
        );
    }
    // Round 30 (G-07): a MAC key makes the trail tamper-evident; without
    // one it is corruption-evident only, and the log says so. A key file or
    // anchor directory that is set and cannot be used refuses the start.
    let audit_options = crate::durable::AuditOptions {
        rotate_bytes,
        max_archives,
        ..Default::default()
    }
    .with_env_values(
        std::env::var(crate::durable::AUDIT_KEY_ENV).ok().as_deref(),
        std::env::var(crate::durable::AUDIT_ANCHOR_ENV)
            .ok()
            .as_deref(),
        &data_dir,
    )?;
    let audit = match AuditLog::open_with_options(audit_path(&data_dir), audit_options) {
        Ok(log) => {
            tracing_log(&format!(
                "audit log: {} (rotate at {} bytes, archives kept: {})",
                audit_path(&data_dir).display(),
                rotate_bytes,
                if max_archives == 0 {
                    "all".to_string()
                } else {
                    max_archives.to_string()
                }
            ));
            match log.key_id() {
                    Some(id) => tracing_log(&format!(
                        "audit trail: hash-chained and MAC'd under key {id} — tamper-evident against anyone without the key; truncation and stale restores are caught only against an anchored checkpoint (`graphite audit checkpoint`)"
                    )),
                    None => tracing::warn!(
                        "audit trail: hash-chained but NOT keyed — corruption-evident only: a writer to the data directory can rewrite it coherently. Set {} to a key file outside the data directory to make it tamper-evident",
                        crate::durable::AUDIT_KEY_ENV
                    ),
                }
            // Check or build every archive's index before the first L8
            // lookup needs it (R-M11, Round 28).
            log.warm_archive_indexes_in_background();
            Some(log)
        }
        Err(e) => {
            // Hard failure, matching what `probe_data_dir_writable` above
            // already promises: "Graphite refuses to start without a
            // durable audit trail (Constitution P9)."
            //
            // This used to log a WARNING and continue with `audit = None`,
            // after which the server accepted verifications and recorded
            // none of them — the probe's stated guarantee contradicted a
            // few hundred lines below it. The probe checks that the
            // DIRECTORY is writable; opening the log can still fail for
            // reasons it cannot see (the file exists and is not writable,
            // a stale lock, a full disk).
            return Err(format!(
                "audit log at {} could not be opened: {e}. Graphite refuses to start \
                     without a durable audit trail (Constitution P9) — an approval nobody \
                     recorded is an approval nobody can reconcile, quarantine against, or \
                     investigate.",
                audit_path(&data_dir).display()
            )
            .into());
        }
    };

    // Wallet policy profile enforcement at the network trust boundary — see
    // `enforce_wallet_profile`. A misconfigured pin was refused above, by
    // `OperatorPolicy::from_env`: an operator who meant to pin a policy must
    // not silently get the caller-controlled behavior instead.
    let pinned_profile = policy.pinned_profile;
    if let Some(p) = pinned_profile {
        tracing_log(&format!(
            "wallet profile PINNED server-side: {p:?} (request-body profiles are ignored)"
        ));
    }
    let allow_permissive_profiles = policy.allow_permissive_profiles;
    if allow_permissive_profiles && pinned_profile.is_none() {
        tracing_log(
            "WARNING: GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1 — a caller may supply a wallet \
             profile that disables the confidence/trust-tier gate entirely",
        );
    }

    // Manifest Registry state (shared contract with the CLI: default
    // `registry_state.json`, override `GRAPHITE_REGISTRY_STATE`). Community
    // submissions accepted via `graphite registry submit` survive restarts
    // and are (C53) merged into the VERIFICATION core's registry, so accepted
    // community manifests resolve at verification time — not just in the
    // dashboard. A missing file is the first-run case.
    //
    // A corrupt or unreadable file refuses to start (audit 2026-10-20). It
    // used to log one line and start with an EMPTY registry: every accepted
    // community manifest silently stopped resolving and every reviewer's
    // reputation was gone, while the CLI, reading the same file, refused it.
    // The next `registry` write would then have saved the empty state over
    // the real one.
    let registry_state_path = std::env::var("GRAPHITE_REGISTRY_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("registry_state.json"));
    let registry_engine = match std::fs::read_to_string(&registry_state_path) {
        Ok(json) => {
            let engine = crate::manifest_registry::ManifestRegistryEngine::from_json(&json)
                .map_err(|e| {
                    format!(
                        "manifest registry: CORRUPT state file {} ({e}). REFUSING TO START rather than serving with an empty registry; restore the file from a backup, or move it aside deliberately to start fresh",
                        registry_state_path.display()
                    )
                })?;
            tracing_log(&format!(
                "manifest registry: loaded {} accepted record(s) from {}",
                engine.records().len(),
                registry_state_path.display()
            ));
            engine
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::manifest_registry::ManifestRegistryEngine::new()
        }
        Err(e) => {
            return Err(format!(
                "manifest registry: state file {} cannot be read ({e}). REFUSING TO START rather than serving with an empty registry",
                registry_state_path.display()
            )
            .into())
        }
    };
    let merged = core.merge_community_manifests(&registry_engine);
    if merged > 0 {
        tracing_log(&format!(
            "manifest registry: merged {merged} community-accepted manifest(s) into the verification registry (C53)"
        ));
    }

    let inflight_limit = limits.inflight_limit;
    tracing_log(&format!(
        "in-flight verification limit: {inflight_limit} (GRAPHITE_MAX_CONCURRENT); excess is shed with 503 + Retry-After rather than left to expire at the {}s request timeout; other routes share a separate pool of {MAX_CONCURRENT_AUXILIARY}, and /health draws on neither",
        REQUEST_TIMEOUT.as_secs()
    ));
    let state = AppState {
        core: Arc::new(core),
        api_key: api_key.clone(),
        admin_key: admin_key.clone(),
        read_key: read_key.clone(),
        audit,
        registry_engine: Arc::new(registry_engine),
        rate: RateLimiter::new(rate_per_sec),
        trust_proxy_hops,
        metrics: Metrics::default(),
        inflight: Arc::new(tokio::sync::Semaphore::new(inflight_limit)),
        inflight_limit,
        aux_inflight: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_AUXILIARY)),
        pinned_profile,
        allow_permissive_profiles,
    };

    tracing_log(&format!(
        "auth: {} | rate limit: {:.0} req/s/IP | CORS origins: {} | body limit: {}KB | timeout: {}s",
        if api_key.is_some() {
            "Bearer API key (GRAPHITE_API_KEY)"
        } else {
            "NONE — GRAPHITE_DEV_MODE=1, unauthenticated, loopback only"
        },
        rate_per_sec,
        if cors_origins.is_empty() {
            "DENIED (default)".to_string()
        } else {
            cors_origins
                .iter()
                .filter_map(|o| o.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ")
        },
        MAX_BODY_SIZE / 1024,
        REQUEST_TIMEOUT.as_secs(),
    ));

    let app = build_app(state, cors_origins);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing_log(&format!("Graphite server listening on {}", addr));

    // Graceful shutdown — SIGTERM (Docker/K8s) and SIGINT (Ctrl+C)
    let shutdown = async {
        #[cfg(unix)]
        {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    tokio::select! {
                        _ = sigterm.recv() => tracing_log("Received SIGTERM - shutting down gracefully"),
                        _ = signal::ctrl_c() => tracing_log("Received SIGINT - shutting down gracefully"),
                    }
                }
                Err(e) => {
                    tracing_log(&format!("Warning: failed to install SIGTERM handler: {}. Falling back to Ctrl-C only.", e));
                    let _ = signal::ctrl_c().await;
                    tracing_log("Received interrupt - shutting down gracefully");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = signal::ctrl_c().await;
            tracing_log("Received interrupt - shutting down gracefully");
        }
    };

    let max_connections = limits.max_connections;
    let max_per_peer = limits.max_per_peer;
    tracing_log(&format!(
        "connection limit: {max_connections} (GRAPHITE_MAX_CONNECTIONS), {} per peer (GRAPHITE_MAX_CONNECTIONS_PER_IP; IPv6 per /64, and {SITE_CONNECTION_FACTOR}x that per /48); a request head must arrive within {}s",
        if max_per_peer == 0 {
            "no limit".to_string()
        } else {
            max_per_peer.to_string()
        },
        HEADER_READ_TIMEOUT.as_secs()
    ));
    let connection_lifetime = limits.connection_lifetime;
    tracing_log(&format!(
        "a connection is closed after {}s (GRAPHITE_CONNECTION_LIFETIME_SECS)",
        connection_lifetime.as_secs()
    ));
    serve_hardened(
        listener,
        app,
        max_connections,
        max_per_peer,
        connection_lifetime,
        shutdown,
    )
    .await?;
    Ok(())
}

/// The server's accept loop (A4-03, 2026-09-29 audit).
///
/// What axum's `serve` did, plus the two bounds it could not give: every
/// connection's request head is read under `HEADER_READ_TIMEOUT` (hyper's
/// timer, which `serve` never installed), and at most `max_connections` are
/// open at once — one more is closed at accept, before anything is read from
/// it. HTTP/1.1 only: every Graphite client speaks it, and the version sniff
/// an HTTP/2-capable builder performs is itself an unbounded read.
/// TCP_NODELAY on every connection (Round 11). On shutdown, open connections
/// finish their in-flight request, for at most `REQUEST_TIMEOUT`.
async fn serve_hardened(
    listener: tokio::net::TcpListener,
    app: Router,
    max_connections: usize,
    max_per_peer: usize,
    connection_lifetime: Duration,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt as _;

    let permits = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let peers = Arc::new(PeerConnections::default());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // EMFILE and friends: back off rather than spin.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };
        // Refusals at accept are caller-triggerable, so each kind is logged
        // at most once per window, with a count (audit 2026-10-20, L4).
        static PEER_CAP_REFUSALS: LogThrottle = LogThrottle::new(REFUSAL_LOG_WINDOW_MS);
        static CONNECTION_CAP_REFUSALS: LogThrottle = LogThrottle::new(REFUSAL_LOG_WINDOW_MS);
        let peer_slot = match peers.claim(remote.ip(), max_per_peer) {
            Ok(slot) => slot,
            Err(refusal) => {
                if let Some(suppressed) = PEER_CAP_REFUSALS.admit() {
                    let what = match refusal {
                        PeerRefusal::Peer => format!("that peer already holds {max_per_peer}"),
                        PeerRefusal::Site => format!(
                            "its IPv6 /48 already holds {}",
                            max_per_peer.saturating_mul(SITE_CONNECTION_FACTOR)
                        ),
                    };
                    tracing::warn!(
                        "connection from {remote} closed at accept: {what} connections (GRAPHITE_MAX_CONNECTIONS_PER_IP){}",
                        suppressed_note(suppressed)
                    );
                }
                drop(stream);
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            if let Some(suppressed) = CONNECTION_CAP_REFUSALS.admit() {
                tracing::warn!(
                    "connection from {remote} closed at accept: {max_connections} connections already open (GRAPHITE_MAX_CONNECTIONS){}",
                    suppressed_note(suppressed)
                );
            }
            drop(stream);
            continue;
        };
        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!("TCP_NODELAY could not be set on an accepted connection: {e}");
        }
        let service =
            app.clone()
                .map_request(move |mut req: axum::http::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(remote));
                    req.map(axum::body::Body::new)
                });
        let connection = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(
                TokioIo::new(stream),
                hyper_util::service::TowerToHyperService::new(service),
            );
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            match tokio::time::timeout(connection_lifetime, connection).await {
                Ok(Err(e)) => tracing::debug!("connection from {remote} ended: {e}"),
                Ok(Ok(())) => {}
                // Dropping the connection closes its socket.
                Err(_) => tracing::debug!(
                    "connection from {remote} closed: open for {}s (GRAPHITE_CONNECTION_LIFETIME_SECS)",
                    connection_lifetime.as_secs()
                ),
            }
            drop(permit);
            drop(peer_slot);
        });
    }
    drop(listener);
    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(REQUEST_TIMEOUT) => {
            tracing_log("shutdown: connections still open after the request timeout were dropped");
        }
    }
    Ok(())
}

fn build_app(state: AppState, cors_origins: Vec<HeaderValue>) -> Router {
    let cors = if cors_origins.is_empty() {
        // Default: no CORS headers — browsers cannot call cross-origin.
        // Server-to-server clients are unaffected.
        tower_http::cors::CorsLayer::new()
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(cors_origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .max_age(Duration::from_secs(3600))
    };

    Router::new()
        .route("/verify", post(verify_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/manifests", get(manifests_handler))
        // P9 lifecycle events Graphite cannot observe itself (signing,
        // submission, confirmation, finalization) — recorded by the caller
        // that actually performed them. See `lifecycle_event_handler`.
        .route("/audit/event", post(lifecycle_event_handler))
        // L8: confirm a submitted transaction on-chain and reconcile it against
        // the verdict Graphite recorded for it.
        .route("/verify/execution", post(execution_handler))
        // Operator control: withdraw a program from trust without a restart.
        // Behind the same API key as everything else; refused outright when no
        // key is configured (see `quarantine_handler`).
        .route(
            "/admin/quarantine",
            post(quarantine_handler).get(quarantine_list_handler),
        )
        // Dashboard read-only API (Constitution P4 — no mutation).
        .route("/api/graph", get(graph_handler))
        .route("/api/confidence-history", get(confidence_history_handler))
        .route("/api/policy-violations", get(policy_violations_handler))
        .route("/api/protocols/top", get(top_protocols_handler))
        .route("/api/registry", get(registry_handler))
        // The programs whose simulation baseline is frozen, by id. On
        // `/health` until the 2026-10-20 audit, which answers without a key;
        // it now carries only the count there.
        .route("/api/frozen-baselines", get(frozen_baselines_handler))
        // Order (Round 19, F-19-14). Each `route_layer` wraps the ones added
        // before it, so the LAST one here runs FIRST: the dev-mode Host
        // check, then rate limit, then auth, then the concurrency permit.
        // This was the reverse — the permit was taken before the caller was
        // authenticated or rate-limited, and a refusal held it while the body
        // drained, so 32 unauthenticated connections trickling a body could
        // hold every permit for the full request timeout and shed all real
        // traffic with 503. Now a request costs a permit only once it is
        // authenticated, within its rate, and fully received.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            concurrency_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            dev_mode_host_middleware,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Certification item: a panicking handler must not drop the connection
        // or destabilize the server — convert the panic to a clean 500 with a
        // generic message (no internal details leaked to the client). Logging
        // of the panic happens in the handler via tracing.
        .layer(CatchPanicLayer::custom(
            |_panic: Box<dyn std::any::Any + Send + 'static>| {
                tracing_log("internal error: handler panicked (caught by CatchPanicLayer)");
                axum::http::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(axum::body::Bytes::from_static(
                        b"{\"error\":\"internal server error\"}",
                    )))
                    .unwrap()
            },
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

/// Answer a request that is being refused before its body was read — a 401,
/// 421, 429 or 503 from the middlewares — WITHOUT leaving that body unread.
///
/// Closing a connection with unread bytes in the socket makes the kernel
/// send RST instead of FIN, and a client still writing its body sees a reset
/// rather than the status: the SDK reports a network error where the server
/// meant "rate limited, retry after 1 s". Found by the Round 11 live probe
/// once the request path was fast enough to answer before the body landed.
/// The body is already bounded by `RequestBodyLimitLayer` (outside these
/// middlewares), so draining it costs at most `MAX_BODY_SIZE` of reads that
/// the network had already delivered.
async fn refuse_after_draining(
    req: axum::http::Request<axum::body::Body>,
    response: Response,
) -> Response {
    // Bounded in TIME as well as size (Round 19, F-19-14): a refused client
    // that trickles its body is not owed ten seconds of this server. Past the
    // bound the connection is closed; a well-behaved client has long since
    // sent its body, and one that has not gets a reset instead of a status.
    let _ = tokio::time::timeout(
        REFUSAL_DRAIN_TIMEOUT,
        axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE),
    )
    .await;
    let mut response = response;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// How long a refused request's body may take to drain (see
/// `refuse_after_draining`).
const REFUSAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// How long an admitted request's body may take to arrive before a
/// verification permit is spent on it (see `concurrency_limit_middleware`).
///
/// 2 s, not 5 (A4-10, 2026-09-29 audit): `REQUEST_TIMEOUT` covers the body
/// read AND the verification, and 5 s of body plus the 6 s RPC budget was
/// past it — a slow upload followed by a slow RPC was cut off at 10 s with a
/// bare 408 and no audit row, the failure the RPC budget was sized to
/// prevent. A verification body is a few kilobytes; the three bounds are now
/// asserted together at the RPC client's construction.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The route a load balancer polls. Open without a key, exempt from the rate
/// limiter and from load shedding (audit 2026-10-20, L3), and cheap: it reads
/// counters, the audit file's size and the archive count, never the trail.
const HEALTH_PATH: &str = "/health";

/// Whether a `Host` header names this machine's loopback interface:
/// `localhost` (or a name under `.localhost`, RFC 6761), any `127.0.0.0/8`
/// address, or `[::1]`, with or without a port.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    // `[v6]:port`, `[v6]`, `name:port`, `v4:port`, `name`, `v4`.
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inner, tail)) if tail.is_empty() || tail.starts_with(':') => inner,
            _ => return false,
        }
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
            Some(_) => return false,
            None => host,
        }
    };
    let name = name.trim_end_matches('.');
    if name.eq_ignore_ascii_case("localhost") || name.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Dev mode answers only to requests addressed to loopback (audit
/// 2026-10-20, L8).
///
/// A keyless instance is bound to loopback, which keeps other machines out
/// but not a web page in the operator's own browser: DNS rebinding points an
/// attacker's domain at 127.0.0.1, and the page's requests then reach this
/// server with `Host: attacker.example`, unauthenticated — `/verify`, the
/// dashboard reads, the lifecycle trail. The browser always sends the name it
/// resolved, so a keyless instance refuses any request whose `Host` is not a
/// loopback name or address. A request with no `Host` at all (HTTP/1.0, or a
/// raw client) is not one a browser makes and is let through. With an API
/// key configured the key is the control and this check does not run.
async fn dev_mode_host_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if state.api_key.is_none() {
        // Two Host headers name two hosts; the first is not the answer
        // (Round 30). Refused as a non-loopback name would be.
        let host = match req.headers().get_all(header::HOST).iter().count() {
            0 => None,
            1 => req
                .headers()
                .get(header::HOST)
                .map(|v| v.to_str().map(is_loopback_host).unwrap_or(false)),
            _ => Some(false),
        };
        if host == Some(false) {
            let refusal = (
                StatusCode::MISDIRECTED_REQUEST,
                Json(serde_json::json!({
                    "error": "this unauthenticated (GRAPHITE_DEV_MODE) instance answers only to requests addressed to a loopback host",
                    "hint": "address it as 127.0.0.1, [::1] or localhost; set GRAPHITE_API_KEY to serve other names",
                })),
            )
                .into_response();
            return refuse_after_draining(req, refusal).await;
        }
    }
    next.run(req).await
}

/// API-key auth. `/health` stays open for load balancers.
async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Judged by the ROUTE the request matched, not the raw path (Round 30):
    // the two agree for every request the router accepts today, but the
    // privilege a request is held to must follow the handler it reaches,
    // whatever spelling of the path reached it.
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    if route == HEALTH_PATH {
        return next.run(req).await;
    }
    // Exactly one Authorization header (Round 30). Two are two claims, and
    // which one a proxy in front checked is not knowable here; refusing is
    // the only answer that does not guess.
    let authorization = req.headers().get_all(header::AUTHORIZATION);
    let provided = match authorization.iter().count() {
        0 => "",
        1 => req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or(""),
        _ => {
            Metrics::inc(&state.metrics.auth_failures);
            let refusal = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "hint": "send exactly one Authorization header",
                })),
            )
                .into_response();
            return refuse_after_draining(req, refusal).await;
        }
    }
    .to_string();
    // The operator surface answers only to the operator key (Round 19,
    // F-19-13). The verify key is held by the agent — the component the
    // threat model already assumes can be prompt-injected — and it used to
    // open `/admin/quarantine` too, so the party a quarantine protects against
    // could lift it. Without an operator key configured the surface does not
    // exist, in dev mode as well.
    if route.starts_with("/admin/") || req.uri().path().starts_with("/admin/") {
        let provided = provided.as_str();
        let refusal = match &state.admin_key {
            None => Some((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "operator endpoints are disabled: GRAPHITE_ADMIN_API_KEY is not configured",
                    "hint": "set GRAPHITE_ADMIN_API_KEY (distinct from GRAPHITE_API_KEY) to enable /admin/*",
                })),
            )),
            Some(admin) if !ct_eq(provided, admin.as_str()) => Some((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "hint": "operator endpoints require the operator key (GRAPHITE_ADMIN_API_KEY); the verify key is not accepted here",
                })),
            )),
            Some(_) => None,
        };
        if let Some(refusal) = refusal {
            Metrics::inc(&state.metrics.auth_failures);
            return refuse_after_draining(req, refusal.into_response()).await;
        }
        return next.run(req).await;
    }
    if let Some(key) = &state.api_key {
        // The read key opens the read-only routes and nothing else (Round
        // 30, K-11); the verify key opens those and the routes that verify
        // and record.
        let read_ok = is_read_route(req.method(), &route)
            && state
                .read_key
                .as_ref()
                .is_some_and(|r| ct_eq(&provided, r.as_str()));
        if !read_ok && !ct_eq(&provided, key.as_str()) {
            Metrics::inc(&state.metrics.auth_failures);
            let refusal = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "hint": "provide a valid Bearer API key (set via GRAPHITE_API_KEY)",
                })),
            )
                .into_response();
            return refuse_after_draining(req, refusal).await;
        }
    }
    next.run(req).await
}

/// Per-IP rate limiting (429 when a client exceeds its bucket).
async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // `/health` is exempt (audit 2026-10-20, L3): it is documented as open
    // for load balancers, and behind a trusted proxy the balancer's own
    // probes all key one bucket — the proxy's — so any client able to land
    // requests in that bucket could fail the balancer's checks and have a
    // healthy node pulled. It costs no audit scan and no RPC.
    if req.uri().path() == HEALTH_PATH {
        return next.run(req).await;
    }
    let ip = rate_limit_key(client_ip(&req, addr, state.trust_proxy_hops));
    if !state.rate.check(ip) {
        Metrics::inc(&state.metrics.rate_limited);
        let refusal = (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            Json(serde_json::json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
        return refuse_after_draining(req, refusal).await;
    }
    next.run(req).await
}

/// Refuse work the server cannot finish, instead of accepting it and letting it
/// expire.
///
/// `try_acquire` rather than `acquire`: queueing here would just move the wait
/// from the RPC to the semaphore and still end at REQUEST_TIMEOUT, which is the
/// behaviour being removed. A shed request is answered immediately with a
/// status the caller can act on.
///
/// Two pools (audit 2026-10-20, M12): `/verify` and `/verify/execution`, the
/// routes that spend verification capacity (the pipeline, the RPC budget),
/// draw on `inflight`; every other route draws on its own smaller pool,
/// `aux_inflight`, so a dashboard read waiting on an archive-scan slot can
/// never hold a verification's permit. `/health` draws on neither (L3): it
/// is a liveness probe, and a balancer that saw it shed would pull a node
/// that is merely busy — saturation is what `graphite_load_shed_total` is
/// for. It used to share the verification pool, which made a busy node
/// look dead.
async fn concurrency_limit_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // The matched route decides the pool, as it decides auth (Round 30).
    let path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    if path == HEALTH_PATH {
        return next.run(req).await;
    }
    let verification = matches!(path.as_str(), "/verify" | "/verify/execution");
    // Receive the body BEFORE taking a permit (Round 19, F-19-14): a permit
    // is a unit of verification capacity, and a client that is still sending
    // is not using any. A body that does not arrive within
    // BODY_READ_TIMEOUT is refused with 408 and never costs a permit.
    let (parts, body) = req.into_parts();
    let bytes =
        match tokio::time::timeout(BODY_READ_TIMEOUT, axum::body::to_bytes(body, MAX_BODY_SIZE))
            .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({ "error": "request body too large or malformed" })),
                )
                    .into_response();
            }
            Err(_) => {
                let mut response = (
                StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({
                    "error": "request body not received in time",
                    "hint": format!("the body must arrive within {}s", BODY_READ_TIMEOUT.as_secs()),
                })),
            )
                .into_response();
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                return response;
            }
        };
    let req = axum::http::Request::from_parts(parts, axum::body::Body::from(bytes));
    if !verification {
        let Ok(permit) = Arc::clone(&state.aux_inflight).try_acquire_owned() else {
            Metrics::inc(&state.metrics.aux_load_shed);
            static AUX_SHED_LOG: LogThrottle = LogThrottle::new(REFUSAL_LOG_WINDOW_MS);
            if let Some(suppressed) = AUX_SHED_LOG.admit() {
                tracing_client_reject(&format!(
                    "at capacity: {MAX_CONCURRENT_AUXILIARY} non-verification requests already in flight, shedding{}",
                    suppressed_note(suppressed)
                ));
            }
            let refusal = (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                Json(serde_json::json!({
                    "error": "server at capacity for this route",
                    "error_type": "LoadShed",
                    "hint": "the server is already running its maximum number of concurrent non-verification requests (dashboard reads, lifecycle reports, operator actions); verifications are unaffected. Retry after the interval in the Retry-After header",
                    "in_flight_limit": MAX_CONCURRENT_AUXILIARY,
                })),
            )
                .into_response();
            return refuse_after_draining(req, refusal).await;
        };
        let response = next.run(req).await;
        drop(permit);
        return response;
    }
    let permit = match Arc::clone(&state.inflight).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            Metrics::inc(&state.metrics.load_shed);
            // WARN, not ERROR, and throttled (audit 2026-10-20, L4): any
            // caller can shed load on demand by sending enough requests, and
            // by this module's own rule (`tracing_client_reject`) what a
            // caller can manufacture must not page anyone. The count is
            // exact in graphite_load_shed_total.
            static SHED_LOG: LogThrottle = LogThrottle::new(REFUSAL_LOG_WINDOW_MS);
            if let Some(suppressed) = SHED_LOG.admit() {
                tracing_client_reject(&format!(
                    "at capacity: {} verifications already in flight, shedding{}",
                    state.inflight_limit,
                    suppressed_note(suppressed)
                ));
            }
            let refusal = (
                StatusCode::SERVICE_UNAVAILABLE,
                // Retry-After is what makes this actionable rather than merely
                // a refusal: the caller is told when to come back. A bare 408
                // told them nothing and invited an immediate retry.
                [(header::RETRY_AFTER, "1")],
                Json(serde_json::json!({
                    "error": "server at capacity",
                    "error_type": "LoadShed",
                    "hint": "the server is already running its maximum number of concurrent verifications; retry after the interval in the Retry-After header",
                    "in_flight_limit": state.inflight_limit,
                })),
            )
                .into_response();
            return refuse_after_draining(req, refusal).await;
        }
    };
    let response = next.run(req).await;
    drop(permit);
    response
}

/// How a verification failure is answered: a caller-fixable 400, or a 500
/// whose detail stays in the log and the audit trail (see `client_message`).
#[derive(Debug, Clone)]
pub enum VerificationHttpError {
    BadRequest(String),
    Internal(String),
}

impl VerificationHttpError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The FULL message, including internal detail. For server-side logging
    /// and the audit trail only — never send this to a client for a 5xx.
    pub fn message(&self) -> &str {
        match self {
            Self::BadRequest(msg) => msg,
            Self::Internal(msg) => msg,
        }
    }

    /// The message that is safe to return to the caller.
    ///
    /// SECURITY (2026-09-05 production audit): a `TransactionBuild` error
    /// whose text didn't match one of a handful of hardcoded substrings fell
    /// through to `Internal` and its RAW internal text was echoed verbatim in
    /// the 500 response body. That couples an information-disclosure boundary
    /// to incidental error wording elsewhere in the codebase — any future
    /// rewording silently changes what external callers can see.
    ///
    /// A 400 message is caller-fixable input feedback and is deliberately
    /// specific (P3 — the caller must be able to act on it). A 500 means a
    /// bug in Graphite, where the caller can act on nothing: they get a
    /// generic message while the detail goes to the log and audit trail.
    pub fn client_message(&self) -> &str {
        match self {
            Self::BadRequest(msg) => msg,
            Self::Internal(_) => {
                "internal verification error — the request was not approved; \
                 see server logs for detail"
            }
        }
    }
}

/// A stable, non-disclosing error CLASS for the client.
///
/// `format!("{:?}", e)` (used for the log line and the audit record) renders
/// the variant's payload too — e.g. `TransactionBuild("<internal detail>")` —
/// so it must never be returned to a caller. This returns only the variant
/// name: enough for a client to branch on programmatically, nothing about
/// Graphite's internals.
fn error_kind(e: &VerificationError) -> &'static str {
    use VerificationError::*;
    match e {
        AccountResolution(_) => "AccountResolution",
        RiskAssessment(_) => "RiskAssessment",
        PolicyEvaluation(_) => "PolicyEvaluation",
        TransactionBuild(_) => "TransactionBuild",
        SemanticGraph(_) => "SemanticGraph",
        Confidence(_) => "Confidence",
        InvalidInput(_) => "InvalidInput",
    }
}

/// Classify verification error into client (400) or server (500) error
fn classify_error(e: &VerificationError) -> VerificationHttpError {
    use crate::account_resolution::AccountResolutionError::*;
    use VerificationError::*;

    match e {
        // Client errors (400) - bad input
        AccountResolution(InvalidAddress(addr)) => {
            VerificationHttpError::BadRequest(format!("Invalid address: {}", addr))
        }
        AccountResolution(AccountCountMismatch { expected, actual }) => {
            VerificationHttpError::BadRequest(format!(
                "Account count mismatch: expected {}, got {}",
                expected, actual
            ))
        }
        AccountResolution(InstructionNotFound(program, disc)) => {
            VerificationHttpError::BadRequest(format!(
                "Instruction not found for program {} with discriminator {}",
                program, disc
            ))
        }
        // Every way `summarize_instruction` can fail is caused by the caller's own
        // input — `InstructionPlanError` is exactly {EmptyProgramId,
        // MissingAccounts, InvalidDiscriminator, InvalidPubkey,
        // InvalidProgramId}, and the builder is a pure function of the plan it
        // is handed. There is no server-side failure mode to report, so the
        // whole class is a client error.
        //
        // This used to decide by substring-matching the error TEXT, defaulting
        // to Internal when nothing matched. The matcher looked for "invalid
        // discriminator" while the builder emitted "instruction discriminator
        // is invalid hex", so every malformed discriminator — `"zzzz"`,
        // `"abc"`, anything odd-length — returned HTTP 500 and logged at ERROR,
        // with a tower_http failure line behind it. It failed closed, so it was
        // never an approval bypass; it was a free way for anyone who could
        // reach the port to manufacture 500s, page an on-call rotation and
        // bury real errors in noise. Matching on prose that lives in another
        // module is a classifier that drifts silently; the default is now the
        // correct one, so a NEW builder error is a 400 by construction rather
        // than a 500 until someone notices.
        //
        // (`load_manifest` also maps into this variant, but that is an operator
        // API and is not reachable from `/verify`.)
        TransactionBuild(msg) => VerificationHttpError::BadRequest(msg.clone()),
        AccountResolution(NoManifest(program_id)) => {
            VerificationHttpError::Internal(format!("No manifest found for program {}", program_id))
        }

        // Server errors (500) - internal failures
        AccountResolution(AccountResolutionError::PdaDerivationFailed { account, reason }) => {
            VerificationHttpError::Internal(format!(
                "PDA derivation failed for {}: {}",
                account, reason
            ))
        }
        Confidence(msg) => {
            VerificationHttpError::Internal(format!("Confidence engine error: {}", msg))
        }
        InvalidInput(msg) => VerificationHttpError::BadRequest(msg.clone()),
        RiskAssessment(msg) => {
            VerificationHttpError::Internal(format!("Risk engine error: {}", msg))
        }
        PolicyEvaluation(msg) => {
            VerificationHttpError::Internal(format!("Policy engine error: {}", msg))
        }
        SemanticGraph(msg) => {
            VerificationHttpError::Internal(format!("Semantic graph error: {}", msg))
        }
    }
}

/// The longest rejection text logged or returned for a body that did not
/// parse (audit 2026-10-20, L5): the bound the audit trail applies to the
/// same text (`durable`'s `MAX_AUDIT_FIELD_CHARS`, 256), with the same
/// truncation marker. The extractor's message quotes the offending input, so
/// a megabyte body produced a megabyte log line and a megabyte response.
const MAX_REJECTION_TEXT_CHARS: usize = crate::durable::MAX_AUDIT_FIELD_CHARS;

/// `text`, bounded to [`MAX_REJECTION_TEXT_CHARS`], saying what was cut.
fn bounded_rejection_text(text: &str) -> String {
    let total = text.chars().count();
    if total <= MAX_REJECTION_TEXT_CHARS {
        return text.to_string();
    }
    let kept: String = text.chars().take(MAX_REJECTION_TEXT_CHARS).collect();
    format!("{kept}… [truncated, {total} chars total]")
}

/// Verify handler — returns 200 on success, 400 on bad input, 500 on internal
/// error, 422 on a body that is not a `VerificationInput`.
///
/// Error classification:
///   400 BAD_REQUEST: client provided invalid input (bad address, wrong account count,
///     unknown discriminator, invalid program ID). These are caller-fixable.
///   500 INTERNAL_SERVER_ERROR: internal failures (risk engine, policy engine,
///     confidence computation, PDA derivation, semantic graph). These indicate
///     bugs in Graphite, not caller errors. Per Constitution P12 (fail-closed),
///     the response body explains the error but the HTTP status tells the client
///     this is a server-side issue, not a transaction rejection.
///
/// The wallet-profile boundary (`enforce_wallet_profile`) lives in
/// `cli::boundary`, shared with `graphite verify` (audit 2026-10-20, L11).
async fn verify_handler(
    State(state): State<AppState>,
    payload: Result<Json<VerificationInput>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<VerificationResult>, (StatusCode, Json<serde_json::Value>)> {
    // A malformed/unparseable body (422 from the Json extractor) is a probing
    // attempt and MUST be audited too — it never reaches the match below, so
    // it is handled here to leave a trail. Counted like every other refusal
    // of a verification request (audit 2026-10-20, L5: it reached neither
    // counter, so a flood of junk bodies was invisible on /metrics).
    let Json(input) = match payload {
        Ok(p) => p,
        Err(rejection) => {
            Metrics::inc(&state.metrics.verify_requests);
            Metrics::inc(&state.metrics.verify_errors);
            let message = bounded_rejection_text(&rejection.body_text());
            // A failed append is counted and reported by the log itself and
            // surfaces as `degraded` on /health. It is not turned into a panic
            // here: the response is already a rejection, so nothing false is
            // claimed by returning it, and a panic would only replace a
            // precise 422 with an opaque 500.
            if let Some(log) = &state.audit {
                if !append_error_off_runtime(
                    log,
                    AuditErrorRecord {
                        timestamp: crate::durable::now_utc_rfc3339(),
                        program_id: "<malformed>".to_string(),
                        instruction_name: "<unparseable>".to_string(),
                        error: message.clone(),
                        error_type: "JsonRejection".to_string(),
                        status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    },
                )
                .await
                {
                    tracing_server_error("audit: error record for a 422 was NOT written");
                }
            }
            tracing_log(&format!("verify: 422 unparseable body — {}", message));
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": message,
                    "error_type": "JsonRejection",
                    "status": StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    "hint": "Fix the request input and retry",
                })),
            ));
        }
    };

    Metrics::inc(&state.metrics.verify_requests);

    // Enforce the wallet policy profile at the trust boundary BEFORE
    // verification: the profile arrives in the same attacker-influenced body
    // as everything else. See `enforce_wallet_profile`.
    let (effective_profile, profile_note) = match enforce_wallet_profile(
        input.wallet_profile,
        state.pinned_profile,
        state.allow_permissive_profiles,
    ) {
        Ok(v) => v,
        Err(msg) => {
            // A4-07 (2026-09-29 audit): a refusal is audited like every other
            // refusal — the 422 above and the verification errors below both
            // leave an error record, and this 400 left none, so probing the
            // profile gate was invisible on the trail.
            Metrics::inc(&state.metrics.verify_errors);
            if let Some(log) = &state.audit {
                if !append_error_off_runtime(
                    log,
                    AuditErrorRecord {
                        timestamp: crate::durable::now_utc_rfc3339(),
                        program_id: input.program_id.clone(),
                        instruction_name: "<wallet_profile refused>".to_string(),
                        error: msg.clone(),
                        error_type: "InvalidInput".to_string(),
                        status: StatusCode::BAD_REQUEST.as_u16(),
                    },
                )
                .await
                {
                    tracing_server_error("audit: error record for a 400 was NOT written");
                }
            }
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": msg,
                    "error_type": "InvalidInput",
                    "status": StatusCode::BAD_REQUEST.as_u16(),
                    "hint": "Fix the request input and retry",
                })),
            ));
        }
    };
    let mut input = input;
    input.wallet_profile = effective_profile;
    let input = input;

    match state.core.verify_async(&input).await {
        Ok(result) => {
            tracing_log(&format!(
                "verify: {} | {} ({}) | confidence={:.2} | {}",
                input.program_id,
                if result.approved {
                    "APPROVED"
                } else {
                    "BLOCKED"
                },
                result.decision.as_str(),
                result.confidence,
                result.audit_trail_id
            ));

            // Durability: append to the audit log before responding (the line
            // is flushed synchronously).
            //
            // NOT best-effort. That comment used to say "never fails the
            // request", and the write's return value was discarded, so a
            // verdict that never reached the trail came back as a clean
            // approval. Graphite's own L8 reconciliation, quarantine decisions
            // and incident response all read that trail; an approval missing
            // from it is one nobody can reconcile against, and the caller had
            // no way to know.
            let mut audit_recorded = true;
            if let Some(log) = &state.audit {
                // GAP-2026-08-06-3: the audit trail records the REAL L3/L8 layer
                // states (never the old phantom `passed: true`). Layers are the
                // single source of truth for the pipeline report.
                let layer_status = |name: &str| -> String {
                    result
                        .layers
                        .iter()
                        .find(|l| l.layer == name)
                        .map(|l| l.status.as_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                };
                audit_recorded = append_off_runtime(
                    log,
                    AuditRecord {
                        // The synchronous construction -> simulation ->
                        // verification operation Graphite actually performs. Its
                        // construction and simulation evidence rides on this same
                        // row (`transaction`, `l3_status`) rather than as separate
                        // rows: they are inseparable from this one call, and
                        // splitting them would triple audit volume without adding
                        // a fact. The stages Graphite does NOT perform arrive via
                        // POST /audit/event.
                        event_type: LifecycleEvent::Verification,
                        timestamp: crate::durable::now_utc_rfc3339(),
                        audit_trail_id: result.audit_trail_id.clone(),
                        content_hash: result.content_hash.clone(),
                        transaction_sha256: match &result.scope {
                            crate::verification::VerificationScope::ArtifactBound {
                                transaction_sha256,
                                ..
                            } => Some(transaction_sha256.clone()),
                            crate::verification::VerificationScope::Descriptive { .. } => None,
                        },
                        program_id: input.program_id.clone(),
                        instruction_name: result.instruction_name.clone(),
                        protocol_name: result.protocol_name.clone(),
                        manifest_version: result.manifest_version.clone(),
                        approved: result.approved,
                        decision: Some(result.decision.as_str().to_string()),
                        executable: Some(result.executable),
                        confidence: result.confidence,
                        risk_status: result.risk_verdict.status.clone(),
                        policy_verdict: result.policy_verdict.clone(),
                        l3_status: layer_status("L3_SimulationVerification"),
                        l8_status: layer_status("L8_ExecutionVerification"),
                        wallet_profile: Some(match &profile_note {
                            Some(note) => format!("{:?} ({note})", input.wallet_profile),
                            None => format!("{:?}", input.wallet_profile),
                        }),
                    },
                )
                .await;
            }

            // A verdict Graphite could not record is a verdict it must not hand
            // back as though it had. Refusing here is loud, which is the point:
            // a full or failing audit disk gets fixed instead of silently
            // producing approvals with no trail behind them.
            //
            // 503 rather than 500 because the condition is operational and
            // transient — the same treatment load shedding gets, and for the
            // same reason: a refusal the caller can act on beats an answer they
            // cannot rely on.
            if !audit_recorded {
                state.core.discard_observation(&result.audit_trail_id);
                Metrics::inc(&state.metrics.verify_errors);
                tracing_server_error(
                    "audit write FAILED for a completed verification — refusing to return the verdict, because an approval with no durable record cannot be reconciled by L8, cannot be quarantined against, and cannot be investigated",
                );
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "verification completed but could not be durably recorded",
                        "error_type": "AuditWriteFailed",
                        "hint": "Graphite refuses to return a verdict it cannot write to the append-only trail (Constitution P9). Check the data volume's writability and free space; graphite_audit_writes_failed_total at /metrics counts these.",
                        "status": 503,
                    })),
                ));
            }

            // On the trail: what this verification observed may now train
            // the baseline (W21).
            state.core.commit_observation(&result.audit_trail_id).await;

            // Counted only once the verdict is on the trail (A4-09,
            // 2026-09-29 audit): the approved counter went up before the
            // append, so a verdict refused with 503 for an unwritable trail
            // still showed on /metrics as an approval that was never given.
            Metrics::inc(if result.approved {
                &state.metrics.verify_approved
            } else {
                &state.metrics.verify_blocked
            });
            let mut result = result;
            if let Some(note) = profile_note {
                // Visible in the response's summary, and on the audit row
                // through its `wallet_profile` field (written above; the
                // summary itself is not on the row) — an overridden policy
                // must never be applied silently.
                result.summary = format!("{} | policy: {}", result.summary, note);
            }
            Ok(Json(result))
        }
        Err(e) => {
            Metrics::inc(&state.metrics.verify_errors);
            let http_error = classify_error(&e);
            let status = http_error.status_code();
            let error_type = format!("{:?}", e);

            let line = format!(
                "verify: {} | ERROR [{}] | {} | {:?}",
                input.program_id,
                if status.is_client_error() {
                    "CLIENT"
                } else {
                    "SERVER"
                },
                e,
                error_type
            );
            if status.is_client_error() {
                tracing_client_reject(&line);
            } else {
                tracing_server_error(&line);
            }

            // Durability: rejected-by-error verifications are audit-worthy
            // too — probing attacks against /verify (malformed payloads,
            // oversized bodies, bad account counts) must leave a trail.
            // The record mirrors AuditRecord but carries the error instead
            // of a verdict.
            // Same reasoning as the 422 path above: a failed append is counted
            // and reported, never a panic, because this response is already a
            // rejection.
            if let Some(log) = &state.audit {
                if !append_error_off_runtime(
                    log,
                    AuditErrorRecord {
                        timestamp: crate::durable::now_utc_rfc3339(),
                        program_id: input.program_id.clone(),
                        instruction_name: input.instruction_discriminator.clone(),
                        error: http_error.message().to_string(),
                        error_type: error_type.clone(),
                        status: status.as_u16(),
                    },
                )
                .await
                {
                    tracing_server_error(&format!(
                        "audit: error record for a {} was NOT written",
                        status.as_u16()
                    ));
                }
            }

            Err((
                status,
                Json(serde_json::json!({
                    // client_message()/error_kind() deliberately withhold
                    // internal detail on a 5xx — the full text is already in
                    // the log line above and the audit record below. A 4xx
                    // still carries the specific, caller-fixable message.
                    "error": http_error.client_message(),
                    "error_type": error_kind(&e),
                    "status": status.as_u16(),
                    "hint": if status.is_client_error() {
                        "Fix the request input and retry"
                    } else {
                        "Internal Graphite error — this is a bug, not a transaction rejection. Report it."
                    },
                })),
            ))
        }
    }
}

/// Liveness + durability health.
///
/// Reports whether the append-only audit trail is actually being written.
/// A verdict the trail cannot take is refused with 503 (see
/// `verify_handler`), but the node stays up and keeps refusing correctly, so
/// a load balancer must keep it: `status` stays "ok" and `degraded` with
/// `audit.writes_failed` is what makes a stopped trail alertable.
///
/// Answers without a key (load balancers), so it says what is wrong without
/// naming what (audit 2026-10-20): the programs whose simulation baseline is
/// frozen are a count here and listed at the authenticated
/// `/api/frozen-baselines`.
async fn health_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit = state.audit.as_ref().map(|a| a.health());
    let mut persistence = state.core.persistence_health();
    // `/health` answers without a key (load balancers), so it says THAT the
    // last snapshot failed, not the error text — which carries the data
    // directory's absolute path (Round 19, F-19-19). The text is in the log
    // and at the authenticated /metrics.
    if persistence.last_error.is_some() {
        persistence.last_error =
            Some("snapshot failed; the error is in the server log".to_string());
    }
    // Every reason a node is degraded, by name. An operator paged on
    // `degraded: true` should not have to diff counters to learn why.
    let mut reasons: Vec<&str> = Vec::new();
    match &audit {
        Some(h) => {
            if h.writes_failed > 0 {
                reasons.push("audit_writes_failed");
            }
            if h.rotations_failed > 0 {
                // The trail is intact but the active file cannot rotate, so
                // it grows without bound and every dashboard poll scans it.
                reasons.push("audit_rotation_failed");
            }
            if h.anchors_failed > 0 {
                // A rotation checkpoint did not reach the anchor directory:
                // the trail since the last one is not anchored.
                reasons.push("audit_anchor_failed");
            }
        }
        // No audit log at all is degraded, not healthy: verification still
        // works, but the P9 trail does not exist.
        None => reasons.push("audit_disabled"),
    }
    if persistence.snapshots_failed > 0 {
        // Trust tiers and baselines earned since the last good snapshot
        // exist only in memory and vanish on restart.
        reasons.push("graph_snapshot_failed");
    }
    // Round 17 (F-16-02): a trusted baseline that has refused MIN_SAMPLES
    // clean executions is frozen — every honest transaction of that program
    // at a different shape is being refused as `SimulationSpoofing`. That is
    // an operator's decision to make (`graphite evidence promote-shadow`),
    // and it cannot be made if nothing reports it.
    let frozen = state.core.frozen_baselines().len();
    if frozen > 0 {
        reasons.push("simulation_baseline_frozen");
    }
    Json(serde_json::json!({
        // `status` stays "ok" while the service can serve traffic so load
        // balancers don't pull a working node; `degraded` is the operator
        // signal.
        "status": "ok",
        "degraded": !reasons.is_empty(),
        "degraded_reasons": reasons,
        "service": "graphite-core",
        "version": env!("CARGO_PKG_VERSION"),
        // Round 30 (G-01): `analysis_only` when no RPC is attached — every
        // verdict from this node is then `executable: false`. Not a
        // degradation (it is how the node was configured), but the first
        // thing an integrator needs to know.
        "verification_mode": if state.core.has_rpc_client() {
            "executable"
        } else {
            "analysis_only"
        },
        "rpc_attached": state.core.has_rpc_client(),
        "audit": match audit {
            Some(h) => serde_json::json!({
                "enabled": true,
                "writes_ok": h.writes_ok,
                "writes_failed": h.writes_failed,
                "active_bytes": h.active_bytes,
                "rotations_ok": h.rotations_ok,
                "rotations_failed": h.rotations_failed,
                "archive_count": h.archive_count,
                // Round 30 (G-07): what the trail's integrity rests on.
                "integrity": if h.tamper_evident { "tamper_evident" } else { "corruption_evident" },
                "chain_head_seq": h.chain_head_seq,
                "anchors_failed": h.anchors_failed,
            }),
            None => serde_json::json!({ "enabled": false }),
        },
        "graph_persistence": persistence,
        // How many programs' trusted baseline has refused at least
        // MIN_SAMPLES clean executions (Round 17, F-16-02). Which ones, at
        // the authenticated /api/frozen-baselines.
        "frozen_baseline_count": frozen,
        // Whether L8 has a second, independent source for inclusion
        // (Round 12). `false` means every reconciliation rests on one RPC.
        "inclusion_witness": state.core.has_inclusion_witness(),
        // Round 30 (G-08): whether that witness is a different provider
        // (null without one), and whether every L8 conclusion requires it.
        "l8_assurance": {
            "witness_independent": state.core.witness_independence().map(|i| i.is_distinct()),
            "high_assurance": state.core.requires_independent_witness(),
        },
        // Roadmap R-M1: programs found redeployed since last seen, and whether
        // an upgrade quarantines the program.
        "program_upgrades": {
            "detected": state.core.program_upgrades_detected(),
            "quarantine_on_upgrade": state.core.quarantine_on_upgrade(),
        },
    }))
}

/// The programs whose trusted simulation baseline is frozen, with how many
/// clean executions each has refused (Round 17, F-16-02). Behind the verify
/// key since the 2026-10-20 audit; `/health` carries the count.
async fn frozen_baselines_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let frozen: Vec<serde_json::Value> = state
        .core
        .frozen_baselines()
        .into_iter()
        .map(|(program_id, refused)| {
            serde_json::json!({
                "program_id": program_id,
                "refused_clean_executions": refused,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": frozen.len(),
        "frozen_baselines": frozen,
    }))
}

/// Prometheus text-format metrics.
///
/// Enterprise deployments had no numeric signal at all before this: no way to
/// alert on auth failures, rate-limit rejections, audit-write failures, or
/// approve/block ratios. Deliberately a small, honest set of counters that
/// are actually maintained — not a large surface of plausible-looking
/// metrics that are never incremented.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    let audit = state.audit.as_ref().map(|a| a.health());
    let mut out = String::with_capacity(1024);
    let mut push = |name: &str, help: &str, kind: &str, value: u64| {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    };
    push(
        "graphite_verify_requests_total",
        "Verification requests that reached the handler.",
        "counter",
        m.verify_requests.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_approved_total",
        "Verifications that returned approved=true.",
        "counter",
        m.verify_approved.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_blocked_total",
        "Verifications that returned approved=false.",
        "counter",
        m.verify_blocked.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_verify_errors_total",
        "Verification requests that failed before producing a result, including bodies that did not parse (422) and verdicts the trail could not record (503).",
        "counter",
        m.verify_errors.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_auth_failures_total",
        "Requests refused by the auth middleware: 401 for a missing or wrong key, 403 for an operator route on an instance with no operator key configured.",
        "counter",
        m.auth_failures.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_rate_limited_total",
        "Requests rejected with 429 by the rate limiter.",
        "counter",
        m.rate_limited.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_load_shed_total",
        "Requests rejected with 503 because the server was already at its in-flight limit.",
        "counter",
        m.load_shed.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_auxiliary_load_shed_total",
        "Non-verification requests (dashboard reads, lifecycle reports, operator actions, /manifests, /metrics) rejected with 503 because their own in-flight pool was full. Verification capacity is separate and unaffected.",
        "counter",
        m.aux_load_shed.load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_request_rejections_total",
        "Requests to /verify/execution, /audit/event and /admin/quarantine refused as malformed (400 or 422); each is also on the audit trail. /verify's are in graphite_verify_errors_total.",
        "counter",
        m.request_rejections
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_lifecycle_events_total",
        "Caller-reported lifecycle events recorded (signing/submission/confirmation/finalization).",
        "counter",
        m.lifecycle_events
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_lifecycle_events_on_blocked_total",
        "Caller-reported lifecycle events whose content_hash was most recently BLOCKED by Graphite: a signing/submission/confirmation of a refused transaction. Page on this.",
        "counter",
        m.lifecycle_on_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_lifecycle_events_unverified_total",
        "Caller-reported lifecycle events whose content_hash has no verification on record in the trail.",
        "counter",
        m.lifecycle_unverified
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_execution_checks_total",
        "L8 reconciliations performed via /verify/execution.",
        "counter",
        m.execution_checks
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_execution_discrepancies_total",
        "L8 reconciliations that found a transaction Graphite BLOCKED executed on-chain: the gate was bypassed. Page on this.",
        "counter",
        m.execution_discrepancies
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_execution_chain_bytes_rejected_total",
        "L8 reconciliations refused because the RPC returned transaction bytes not bound to the signature (wrong first slot, or the signature does not verify under the fee payer). A faulty or hostile RPC.",
        "counter",
        m.execution_chain_bytes_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_execution_chain_inconsistent_total",
        "L8 reconciliations where the primary RPC gave two accounts of one signature (slot or outcome differ between getSignatureStatuses and getTransaction). No positive conclusion is drawn from such an RPC.",
        "counter",
        m.execution_chain_inconsistent
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_execution_witness_disagreements_total",
        "L8 reconciliations where the inclusion witness disagreed with the primary RPC about a signature, or could not be consulted. Sustained disagreement means one of the two endpoints is wrong about the chain.",
        "counter",
        m.execution_witness_disagreements
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_lifecycle_sequence_anomalies_total",
        "Lifecycle reports that sat wrongly against the rows already on record for their transaction: a duplicate, an out-of-order or unpreceded stage, or a signature that differs from the one already attached. The last of these means one report is false.",
        "counter",
        m.lifecycle_sequence_anomalies
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    push(
        "graphite_audit_writes_ok_total",
        "Audit records successfully appended.",
        "counter",
        audit.map(|h| h.writes_ok).unwrap_or(0),
    );
    push(
        "graphite_program_upgrades_detected_total",
        "Manifested programs found redeployed, or with a new upgrade authority, since Graphite last saw them (roadmap R-M1).",
        "counter",
        state.core.program_upgrades_detected(),
    );
    push(
        "graphite_audit_writes_failed_total",
        "Audit records that failed to append (durability is degraded).",
        "counter",
        audit.map(|h| h.writes_failed).unwrap_or(0),
    );
    push(
        "graphite_audit_active_bytes",
        "Size of the active audit log file in bytes.",
        "gauge",
        audit.map(|h| h.active_bytes).unwrap_or(0),
    );
    push(
        "graphite_audit_rotations_ok_total",
        "Audit log rotations completed.",
        "counter",
        audit.map(|h| h.rotations_ok).unwrap_or(0),
    );
    push(
        "graphite_audit_rotations_failed_total",
        "Audit log rotations that failed; the active file keeps growing (degraded).",
        "counter",
        audit.map(|h| h.rotations_failed).unwrap_or(0),
    );
    push(
        "graphite_audit_archive_count",
        "Rotated audit archives on disk.",
        "gauge",
        audit.map(|h| h.archive_count).unwrap_or(0),
    );
    push(
        "graphite_audit_tamper_evident",
        "1 when new audit records are MAC'd under an operator key (tamper-evident), 0 when the hash chain is unkeyed (corruption-evident only).",
        "gauge",
        u64::from(audit.is_some_and(|h| h.tamper_evident)),
    );
    push(
        "graphite_audit_anchor_writes_failed_total",
        "Rotation checkpoints that could not be written to GRAPHITE_AUDIT_ANCHOR_DIR (degraded).",
        "counter",
        audit.map(|h| h.anchors_failed).unwrap_or(0),
    );
    let persistence = state.core.persistence_health();
    push(
        "graphite_graph_snapshots_ok_total",
        "Semantic-graph snapshots committed to the data directory.",
        "counter",
        persistence.snapshots_ok,
    );
    push(
        "graphite_graph_snapshots_failed_total",
        "Semantic-graph snapshots that failed; earned state exists only in memory (degraded).",
        "counter",
        persistence.snapshots_failed,
    );
    push(
        "graphite_audit_enabled",
        "1 when an audit log is attached, 0 otherwise.",
        "gauge",
        u64::from(audit.is_some()),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out)
}

/// Body for `POST /audit/event`.
#[derive(serde::Deserialize)]
struct LifecycleEventBody {
    event_type: LifecycleEvent,
    /// Join key back to the verification that approved this transaction —
    /// the instruction-level one. Required for compatibility; `audit_trail_id`
    /// or `transaction_sha256` should accompany it, because `content_hash`
    /// alone names every transaction carrying that instruction.
    content_hash: String,
    #[serde(default)]
    audit_trail_id: Option<String>,
    /// The exact transaction this event is about (`scope.transaction_sha256`).
    #[serde(default)]
    transaction_sha256: Option<String>,
    #[serde(default)]
    transaction_signature: Option<String>,
    #[serde(default)]
    reported_by: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

/// Body for `POST /verify/execution`.
#[derive(Debug, serde::Deserialize)]
struct ExecutionBody {
    /// The on-chain signature to confirm.
    signature: String,
    /// The `content_hash` of the verification this execution corresponds to.
    ///
    /// Optional, but without it there is nothing to reconcile against and the
    /// endpoint can only report chain status. The caller asserting the link is
    /// caller-attested, exactly like the P9 lifecycle events: Graphite cannot
    /// prove a signature is the execution of a verification it performed
    /// earlier, and claiming otherwise would put fabricated certainty in the
    /// audit trail.
    #[serde(default)]
    content_hash: Option<String>,
    /// The exact transaction (`scope.transaction_sha256`) this execution is
    /// the submission of. More exact than `content_hash`; still
    /// caller-attested, and cross-checked against the chain's bytes.
    #[serde(default)]
    transaction_sha256: Option<String>,
    /// The exact verification (`audit_trail_id`). The most exact key a
    /// caller can supply; cross-checked the same way.
    #[serde(default)]
    audit_trail_id: Option<String>,
    /// Who is reporting this, recorded on the audit trail.
    #[serde(default)]
    reported_by: Option<String>,
}

/// What one of the handlers below answers.
type HandlerResult = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

/// Count and audit a malformed request to a route other than `/verify`, as
/// `/verify` counts and audits its own (audit 2026-10-20).
///
/// `/verify/execution`, `/audit/event` and `/admin/quarantine` answered 400
/// and 422 with no counter and no audit row, so probing them — forged keys,
/// junk signatures, oversized fields — left no trace on the trail `/verify`'s
/// probes land on. A 422's extractor text is bounded as `/verify`'s is (L5).
/// Responses that are not refusals of the request's shape (401/403, 503) are
/// left as they are.
async fn account_for_rejection(
    state: &AppState,
    route: &'static str,
    program_id: Option<String>,
    result: HandlerResult,
) -> HandlerResult {
    let Err((status, Json(mut body))) = result else {
        return result;
    };
    if status != StatusCode::BAD_REQUEST && status != StatusCode::UNPROCESSABLE_ENTITY {
        return Err((status, Json(body)));
    }
    Metrics::inc(&state.metrics.request_rejections);
    let error = bounded_rejection_text(body.get("error").and_then(|v| v.as_str()).unwrap_or(""));
    if status == StatusCode::UNPROCESSABLE_ENTITY {
        body["error"] = serde_json::Value::String(error.clone());
    }
    let error_type = body
        .get("error_type")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if status == StatusCode::UNPROCESSABLE_ENTITY {
                "JsonRejection".to_string()
            } else {
                "InvalidInput".to_string()
            }
        });
    if let Some(log) = &state.audit {
        let recorded = append_error_off_runtime(
            log,
            AuditErrorRecord {
                timestamp: crate::durable::now_utc_rfc3339(),
                program_id: program_id
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| "<none>".to_string()),
                instruction_name: route.to_string(),
                error,
                error_type,
                status: status.as_u16(),
            },
        )
        .await;
        if !recorded {
            tracing_server_error(&format!(
                "audit: error record for a {} on {route} was NOT written",
                status.as_u16()
            ));
        }
    }
    Err((status, Json(body)))
}

/// `POST /verify/execution`: [`execution`], its refusals accounted for.
async fn execution_handler(
    State(state): State<AppState>,
    payload: Result<Json<ExecutionBody>, axum::extract::rejection::JsonRejection>,
) -> HandlerResult {
    let result = execution(State(state.clone()), payload).await;
    account_for_rejection(&state, "POST /verify/execution", None, result).await
}

/// `POST /audit/event`: [`lifecycle_event`], its refusals accounted for.
async fn lifecycle_event_handler(
    State(state): State<AppState>,
    payload: Result<Json<LifecycleEventBody>, axum::extract::rejection::JsonRejection>,
) -> HandlerResult {
    let result = lifecycle_event(State(state.clone()), payload).await;
    account_for_rejection(&state, "POST /audit/event", None, result).await
}

/// `POST /admin/quarantine`: [`quarantine`], its refusals accounted for, one
/// operator action at a time.
///
/// Serialized (audit 2026-10-20): `quarantine` reads whether the program is
/// already quarantined and then acts, and two requests on different workers
/// could both read "not quarantined" and both append a quarantine record —
/// or a lift's undo (W21) could land between another request's read and its
/// act. Operator actions are rare; holding one lock across the read, the
/// change and the audit append makes each atomic. An async lock, held across
/// the append's await: a request cut off by the timeout releases it while its
/// append finishes on the blocking pool, but by then its change is already
/// in force and visible to the next reader, so the next one cannot act on a
/// stale read.
async fn quarantine_handler(
    State(state): State<AppState>,
    payload: Result<Json<QuarantineBody>, axum::extract::rejection::JsonRejection>,
) -> HandlerResult {
    static OPERATOR_ACTIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one_at_a_time = OPERATOR_ACTIONS.lock().await;
    let program_id = payload
        .as_ref()
        .ok()
        .map(|Json(b)| b.program_id.trim().to_string());
    let result = quarantine(State(state.clone()), payload).await;
    account_for_rejection(&state, "POST /admin/quarantine", program_id, result).await
}

/// L8 — Execution Verification, the post-submission half of the pipeline.
///
/// Every verification response already says "audit_trail_id bound to
/// transaction for future L8 replay". Until 2026-09-07 there was no replay:
/// `verify_execution` existed in the library, was unit-tested, and was reachable
/// from no HTTP route and no CLI command, so a deployed Graphite could not
/// perform execution verification at all. One of the eight advertised layers was
/// documented, tested, and unreachable.
///
/// What makes this a control rather than a status lookup is the reconciliation.
/// Graphite holds an append-only record of what it decided; the chain holds what
/// happened. The outcome worth paging on is `BlockedButExecuted` — a transaction
/// Graphite refused that was submitted anyway. That means the gate was bypassed
/// rather than obeyed, and no layer inside a verification request can ever see
/// it, because it happens entirely outside one.
///
/// Fail-closed: no RPC client, an RPC failure, or no audit log yields
/// `Unavailable`. An unavailable check reports that it is unavailable; it never
/// reports a confirmation.
async fn execution(
    State(state): State<AppState>,
    payload: Result<Json<ExecutionBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Json(body) = payload.map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": e.body_text(),
                "error_type": "JsonRejection",
            })),
        )
    })?;

    let signature = body.signature.trim().to_string();
    if signature.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "signature is required" })),
        ));
    }
    // A base58 Solana signature is 64 bytes => 87-88 characters. Bounding this
    // keeps an oversized value out of the log line and the audit record, the
    // same reasoning as the identifier caps on /verify.
    if signature.len() > MAX_SIGNATURE_CHARS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "signature is {} characters; a base58 Solana signature is at most 88",
                    signature.len()
                ),
            })),
        ));
    }
    if let Err(why) = signature_shape(&signature) {
        // Refused here rather than sent to the RPC: a value that is not a
        // signature cannot have executed, and forwarding it spends an RPC
        // call — two with a witness — per junk request (Round 12).
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": why })),
        ));
    }
    if let Some(h) = body.content_hash.as_deref() {
        let h = h.trim();
        if h.len() != 16 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "content_hash is {} characters; a Graphite content_hash is 16 lowercase hexadecimal characters",
                        h.len()
                    ),
                })),
            ));
        }
    }
    if let Some(t) = body.transaction_sha256.as_deref() {
        if !is_sha256_hex(t.trim()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "transaction_sha256 is {} characters; a SHA-256 is 64 lowercase hexadecimal characters",
                        t.trim().len()
                    ),
                })),
            ));
        }
    }
    if let Some(id) = body.audit_trail_id.as_deref() {
        if id.chars().count() > MAX_LIFECYCLE_ID_CHARS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("audit_trail_id is {} characters; the maximum is {MAX_LIFECYCLE_ID_CHARS}", id.chars().count()),
                })),
            ));
        }
    }
    if let Some(r) = body.reported_by.as_deref() {
        let n = r.chars().count();
        if n > MAX_LIFECYCLE_ID_CHARS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("reported_by is {n} characters; the maximum is {MAX_LIFECYCLE_ID_CHARS}"),
                })),
            ));
        }
    }

    let audit = state.audit.as_ref();
    let result = state
        .core
        .audit_execution(
            &signature,
            crate::verification::ExecutionKeys {
                content_hash: body.content_hash.as_deref().map(str::trim),
                transaction_sha256: body.transaction_sha256.as_deref().map(str::trim),
                audit_trail_id: body.audit_trail_id.as_deref().map(str::trim),
            },
            audit,
        )
        .await;

    // P9: the reconciliation is a lifecycle-grade fact about a transaction
    // Graphite verified, and a discrepancy is the single most important thing
    // this system can record. It goes on the same append-only trail.
    // Round 19 (F-19-17): this row is written as OBSERVED by Graphite, so
    // the keys that link it to a verification must be ones Graphite
    // observed: the chain's bytes, bound to this signature. An attribution
    // through the caller's `audit_trail_id` or `transaction_sha256` is the
    // caller's claim — with a fabricated signature and a victim's id (listed
    // by /api/confidence-history) it wrote a Graphite-attested link between
    // the two, and the victim's honest report then read as the conflict.
    // Such a claim is still recorded, in the detail and labelled as one,
    // and it is not indexed.
    let chain_attributed = matches!(
        result.attribution,
        crate::verification::ExecutionAttribution::Chain
    );
    let caller_claims: Vec<String> = [
        body.audit_trail_id
            .as_deref()
            .map(|v| format!("audit_trail_id {}", v.trim())),
        body.transaction_sha256
            .as_deref()
            .map(|v| format!("transaction_sha256 {}", v.trim())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let recorded = match audit {
        Some(log) => {
            append_lifecycle_off_runtime(
                log,
                LifecycleEventRecord {
                    // A confirmation only when L8 saw one (audit 2026-10-20,
                    // M4): included at cluster-backed commitment. Anything
                    // else — unknown, `processed` only, unavailable — is a
                    // check, recorded as such and outside the lifecycle order.
                    event_type: if matches!(
                        result.chain_status,
                        crate::verification::ExecutionVerification::Confirmed { commitment, .. }
                            if commitment.is_cluster_backed()
                    ) {
                        LifecycleEvent::Confirmation
                    } else {
                        LifecycleEvent::ExecutionCheck
                    },
                    timestamp: crate::durable::now_utc_rfc3339(),
                    // Trimmed, as it was validated and looked up (audit
                    // 2026-10-20): the row carried the caller's raw value,
                    // padding and all, so it never matched the hash it named.
                    content_hash: result
                        .recorded_content_hash
                        .clone()
                        .or_else(|| body.content_hash.as_deref().map(|h| h.trim().to_string()))
                        .unwrap_or_default(),
                    verdict_on_record: None,
                    verdict_on_record_key: None,
                    // The exact keys go on this signature's row only when the
                    // attribution IS exact. A `content_hash` attribution names *a*
                    // transaction carrying the instruction; writing that record's
                    // id and digest here would state, on a row keyed by this
                    // signature, that this signature is that transaction — a link
                    // the trail then reports as a conflict against a truthful
                    // report (found by the Round 12 probe). The detail still says
                    // what was resolved and by which key.
                    transaction_sha256: result.chain_transaction_sha256.clone().or_else(|| {
                        chain_attributed
                            .then(|| result.recorded_transaction_sha256.clone())
                            .flatten()
                    }),
                    audit_trail_id: if chain_attributed {
                        result.recorded_audit_trail_id.clone()
                    } else {
                        None
                    },
                    transaction_signature: Some(signature.clone()),
                    reported_by: body.reported_by.clone(),
                    detail: Some(format!(
                        "L8 reconciliation: {:?}; attribution: {:?}; assurance: {}{}{}{}",
                        result.reconciliation,
                        result.attribution,
                        result.inclusion_assurance.as_str(),
                        if caller_claims.is_empty() || chain_attributed {
                            String::new()
                        } else {
                            format!(
                        "; linked by the caller's claim, not by chain bytes (not indexed): {}",
                        caller_claims.join(", ")
                    )
                        },
                        if result.caller_keys_disagree.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "; caller keys disagree: {}",
                                result.caller_keys_disagree.join(" | ")
                            )
                        },
                        match (
                            &result.chain_bytes_rejected,
                            &result.chain_bytes_unavailable,
                            &result.chain_inconsistent,
                            &result.inclusion_witness,
                        ) {
                            (Some(why), _, _, _) => format!("; chain bytes rejected: {why}"),
                            (None, unavailable, inconsistent, witness) => {
                                let mut tail = String::new();
                                if let Some(why) = unavailable {
                                    tail.push_str(&format!("; chain bytes unavailable: {why}"));
                                }
                                if let Some(why) = inconsistent {
                                    tail.push_str(&format!("; RPC inconsistent: {why}"));
                                }
                                if let Some(w) = witness {
                                    tail.push_str(&format!(
                                        "; witness {}: {}",
                                        if w.agrees { "agrees" } else { "DISAGREES" },
                                        w.detail
                                    ));
                                }
                                tail
                            }
                        }
                    )),
                    observed_by_graphite: true,
                    sequence_anomalies: Vec::new(),
                },
            )
            .await
        }
        None => false,
    };

    Metrics::inc(&state.metrics.execution_checks);
    if result.reconciliation.is_discrepancy() {
        // Loud on purpose. This is Graphite telling the operator that its own
        // decision did not govern the wallet.
        Metrics::inc(&state.metrics.execution_discrepancies);
        tracing_server_error(&format!(
            "L8 DISCREPANCY: signature {} executed on-chain but Graphite BLOCKED it (audit_trail_id {:?})",
            signature, result.recorded_audit_trail_id
        ));
    }
    if let Some(why) = &result.chain_bytes_rejected {
        // The RPC handed back bytes that are not this signature's. Nothing
        // downstream of a substituting RPC can be trusted, so this is an
        // operator-level alarm, not a client-level warning.
        Metrics::inc(&state.metrics.execution_chain_bytes_rejected);
        tracing_server_error(&format!(
            "L8 CHAIN BYTES REJECTED for signature {signature}: {why}"
        ));
    }
    if let Some(why) = &result.chain_inconsistent {
        Metrics::inc(&state.metrics.execution_chain_inconsistent);
        tracing_server_error(&format!(
            "L8 RPC INCONSISTENT about signature {signature}: {why}"
        ));
    }
    if let Some(w) = &result.inclusion_witness {
        if !w.agrees {
            Metrics::inc(&state.metrics.execution_witness_disagreements);
            tracing_server_error(&format!(
                "L8 WITNESS DISAGREES about signature {signature}: {}",
                w.detail
            ));
        }
    }

    let outcome = serde_json::json!({
        "signature": result.signature,
        "chain_status": result.chain_status,
        "recorded_approved": result.recorded_approved,
        "recorded_audit_trail_id": result.recorded_audit_trail_id,
        "recorded_transaction_sha256": result.recorded_transaction_sha256,
        "reconciliation": result.reconciliation,
        "discrepancy": result.reconciliation.is_discrepancy(),
        "attribution": result.attribution,
        "chain_transaction_sha256": result.chain_transaction_sha256,
        "caller_keys_disagree": result.caller_keys_disagree,
        "chain_bytes_rejected": result.chain_bytes_rejected,
        "chain_bytes_unavailable": result.chain_bytes_unavailable,
        "chain_inconsistent": result.chain_inconsistent,
        "inclusion_witness": result.inclusion_witness,
        "inclusion_assurance": result.inclusion_assurance,
        "recorded_verdicts": result.recorded_verdicts,
        "audit_recorded": recorded,
    });
    if !recorded && audit.is_some() {
        // The reconciliation is still returned — an operator looking at a
        // discrepancy must see it — but under a status that says the trail
        // did not take it. This used to be an `assert!`, which turned a full
        // audit disk into a panic and an opaque 500 that hid the
        // reconciliation entirely.
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "audit write failed — this reconciliation was NOT recorded",
                "error_type": "AuditUnavailable",
                "outcome": outcome,
            })),
        ));
    }
    Ok(Json(outcome))
}

#[derive(Debug, serde::Deserialize)]
struct QuarantineBody {
    program_id: String,
    /// Why. Required when quarantining; ignored when lifting.
    #[serde(default)]
    reason: Option<String>,
    /// `false` (the default) quarantines; `true` lifts an active quarantine.
    #[serde(default)]
    lift: bool,
    /// Who is doing this, recorded on the audit trail. Optional but strongly
    /// encouraged — "someone with the API key" is a poor incident record.
    #[serde(default)]
    reported_by: Option<String>,
}

/// Refuse an operator action on a server with no API key configured.
///
/// Everywhere else an absent key means "dev mode, unauthenticated". That is
/// tolerable for read paths and for `/verify`, which mutates only earned
/// baselines. It is not tolerable here: quarantine forces a program's tier to
/// Unknown, which blocks it for every wallet profile with a tier floor, so an
/// unauthenticated instance would be handing that switch to anyone who can
/// reach the port. The server already refuses to bind a non-loopback address
/// without a key; this refuses the operation itself even on loopback.
fn require_operator_auth(state: &AppState) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // `auth_middleware` has already required the operator key on `/admin/*`;
    // this is the handler's own refusal, so an operator action can never run
    // on an instance with no operator key even if it is routed differently.
    if state.admin_key.is_some() {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "operator endpoints require GRAPHITE_ADMIN_API_KEY to be configured",
            "hint": "an instance without an operator key must not expose a switch that can withdraw any program from trust",
        })),
    ))
}

/// A short, stable identifier for the operator key: the first 8 bytes of its
/// SHA-256, hex. Recorded on the audit trail as who acted, so the record
/// names a credential rather than whatever `reported_by` string the caller
/// chose (Round 19, F-19-13). It identifies a key without disclosing it.
fn operator_key_id(state: &AppState) -> String {
    use sha2::{Digest, Sha256};
    match &state.admin_key {
        Some(k) => hex::encode(&Sha256::digest(k.as_bytes())[..8]),
        None => "none".to_string(),
    }
}

/// The longest quarantine reason recorded. A reason is an advisory id and a
/// sentence, not a document; unbounded, one call could append a megabyte to
/// a record that is kept forever and rewritten with every snapshot.
const MAX_QUARANTINE_REASON_CHARS: usize = 1024;

/// Withdraw a program from trust, or restore it (ARCHITECTURE.md 3.8).
///
/// The change takes effect immediately for this process AND is persisted to
/// the durable semantic graph, so it survives a restart. Both directions are
/// appends (P4): the history keeps the pre-quarantine record, the quarantine,
/// and the lift.
///
/// Deliberately operator-triggered rather than automatic — see
/// `GraphiteCore::quarantine_program` for the recorded tradeoff (P14): a
/// threshold on request traffic would hand a denial of service to anyone able
/// to send requests, since they choose the inputs those checks judge.
async fn quarantine(
    State(state): State<AppState>,
    payload: Result<Json<QuarantineBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_operator_auth(&state)?;
    let Json(body) = payload.map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": e.body_text(),
                "error_type": "JsonRejection",
            })),
        )
    })?;

    let program_id = body.program_id.trim().to_string();
    if program_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "program_id is required" })),
        ));
    }
    // Round 19 (F-19-15): a program id is a 32-byte base58 public key.
    // Anything else can never match a program the gate verifies, and every
    // accepted call appends a record that lives forever.
    if crate::solana_types::Pubkey::from_base58(&program_id).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "program_id is not a base58-encoded 32-byte public key",
                "error_type": "QuarantineRejected",
            })),
        ));
    }
    if body
        .reason
        .as_deref()
        .is_some_and(|r| r.trim().chars().count() > MAX_QUARANTINE_REASON_CHARS)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("reason is longer than {MAX_QUARANTINE_REASON_CHARS} characters"),
                "error_type": "QuarantineRejected",
            })),
        ));
    }
    // Idempotent: quarantining a program that is already quarantined changes
    // nothing and appends nothing.
    let already = state
        .core
        .quarantined_programs()
        .iter()
        .any(|(p, _)| p == &program_id);
    if !body.lift && already {
        return Ok(Json(serde_json::json!({
            "program_id": program_id,
            "quarantined": true,
            "already_quarantined": true,
            "note": "the program was already quarantined; nothing was changed or recorded",
        })));
    }
    // Tests only: hold the window between the read above and the change below
    // open, so a test can show `quarantine_handler`'s lock is what closes it
    // (the read and the change are microseconds apart otherwise).
    #[cfg(test)]
    if body.reason.as_deref() == Some(QUARANTINE_RACE_WINDOW_REASON) {
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // Kept so a lift that cannot be recorded can be undone (W21, below).
    let reason_before_lift = state
        .core
        .quarantined_programs()
        .into_iter()
        .find(|(p, _)| p == &program_id)
        .map(|(_, reason)| reason);
    let outcome = if body.lift {
        state.core.lift_program_quarantine_durably(&program_id)
    } else {
        let reason = body.reason.clone().unwrap_or_default();
        state.core.quarantine_program_durably(&program_id, &reason)
    };

    let persisted = match outcome {
        Ok(persisted) => persisted,
        Err(e) => {
            // These are caller-fixable (unknown program, not quarantined,
            // missing reason), so the detail is genuinely useful — unlike an
            // internal error, whose detail is never disclosed.
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": e.to_string(),
                    "error_type": "QuarantineRejected",
                })),
            ));
        }
    };
    if let Err(e) = &persisted {
        tracing_server_error(&format!(
            "operator action on {program_id} is in force but NOT persisted; it ends at the next restart: {e}"
        ));
    }

    // P9: withdrawing or restoring trust is a lifecycle-grade fact about the
    // gate itself. Recording it on the same append-only trail is what makes
    // "why was this blocked in production last Tuesday" answerable.
    // The action has already taken effect and is not reverted if the trail
    // cannot take the record: un-quarantining a program because the audit
    // disk is full would be failing open on the gate to protect the log.
    // The response says whether the record landed, and the log's own counters
    // mark the node degraded.
    let audit_recorded = if let Some(log) = &state.audit {
        append_lifecycle_off_runtime(
            log,
            LifecycleEventRecord {
                event_type: LifecycleEvent::OperatorAction,
                timestamp: crate::durable::now_utc_rfc3339(),
                verdict_on_record: None,
                verdict_on_record_key: None,
                transaction_sha256: None,
                content_hash: program_id.clone(),
                audit_trail_id: None,
                transaction_signature: None,
                // Who acted is the credential that authorized it; the caller's
                // own label is kept, marked as a claim.
                reported_by: Some(match body.reported_by.as_deref().map(str::trim) {
                    Some(label) if !label.is_empty() => format!(
                        "operator key {} (label claimed by caller: {})",
                        operator_key_id(&state),
                        label.chars().take(128).collect::<String>()
                    ),
                    _ => format!("operator key {}", operator_key_id(&state)),
                }),
                detail: Some(if body.lift {
                    format!("quarantine lifted for {program_id}")
                } else {
                    format!(
                        "quarantined {program_id}: {}",
                        body.reason.as_deref().unwrap_or("").trim()
                    )
                }),
                observed_by_graphite: true,
                sequence_anomalies: Vec::new(),
            },
        )
        .await
    } else {
        false
    };
    if !audit_recorded && body.lift {
        // W21 (external review, verified 2026-10-03): the reasoning above
        // keeps a QUARANTINE in force when the trail cannot record it, because
        // undoing it would fail open. The same reasoning refuses a LIFT that
        // cannot be recorded: restoring trust with no record of who restored
        // it is the failing-open direction. The quarantine is put back.
        let restored = state.core.quarantine_program_durably(
            &program_id,
            reason_before_lift
                .as_deref()
                .unwrap_or("quarantine restored"),
        );
        tracing_server_error(&format!(
            "audit: the quarantine lift on {program_id} could not be recorded, so it was not applied (quarantine restored: {})",
            if restored.is_ok() { "yes" } else { "NO" }
        ));
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "the audit trail could not record the lift, so the quarantine stays in force",
                "error_type": "AuditUnavailable",
                "program_id": program_id,
                "quarantined": restored.is_ok(),
            })),
        ));
    }
    if !audit_recorded {
        tracing_server_error(&format!(
            "audit: operator action on {program_id} took effect but was NOT recorded"
        ));
    }

    // Deliberately named `earned_trust_tier`, not `trust_tier`.
    //
    // This is what the program has EARNED from evidence. It is the effective
    // tier while quarantined (the verify path forces Unknown), but after a lift
    // the two diverge: verification takes the greater of the earned tier and
    // the manifest's own capped claim, so a lifted program with no earned
    // evidence reports Unknown here and verifies at OfficialManifest. Found
    // during a live smoke test, where the unqualified name read as "the lift
    // did not work". A field named `trust_tier` that is not the tier
    // verification uses is worse than no field.
    let earned = state
        .core
        .program_behavior(&program_id)
        .map(|b| format!("{:?}", b.trust_tier));

    Ok(Json(serde_json::json!({
        "program_id": program_id,
        "quarantined": !body.lift,
        "earned_trust_tier": earned,
        "note": if body.lift {
            "verification uses the greater of this and the manifest's own capped tier (P7)"
        } else {
            "verification forces Unknown and hard-blocks while quarantined"
        },
        // Whether the change reached disk. It is in force either way; one
        // that is not persisted ends at the next restart (Round 19, F-19-12).
        "persisted": persisted.is_ok(),
        "audit_recorded": audit_recorded,
    })))
}

/// Every currently quarantined program and why.
async fn quarantine_list_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_operator_auth(&state)?;
    let programs: Vec<serde_json::Value> = state
        .core
        .quarantined_programs()
        .into_iter()
        .map(|(program_id, reason)| serde_json::json!({ "program_id": program_id, "reason": reason }))
        .collect();
    Ok(Json(serde_json::json!({
        "count": programs.len(),
        "quarantined": programs,
    })))
}

/// The one quarantine reason whose requests are held between the
/// already-quarantined read and the change in tests (see `quarantine`).
#[cfg(test)]
const QUARANTINE_RACE_WINDOW_REASON: &str = "race-window-test";

/// The one audit trail id whose lifecycle reports are held between the
/// history read and the append in tests (see `lifecycle_event`).
#[cfg(test)]
const RACE_WINDOW_TRAIL_ID: &str = "gr-cafecafecafecafe";

/// Record a lifecycle event for a stage Graphite does not itself perform
/// (Constitution P9).
///
/// P9 requires the full transaction lifecycle to be auditable. Graphite
/// genuinely observes construction, simulation and verification, and records
/// those on the verification row. It does NOT sign, submit, or watch the
/// chain — only the caller knows when those happened, so this endpoint is how
/// they enter the same append-only trail, keyed by `content_hash` so the whole
/// lifecycle reconciles to one transaction.
///
/// The record is explicitly an ATTESTATION, not a proof: Graphite cannot
/// confirm a signing it did not perform. `reported_by` names the reporter and
/// the record says what was reported. Synthesizing these events server-side
/// instead would put fabricated history in an audit trail, which is worse than
/// the gap it would paper over.
///
/// Self-observed event types are REJECTED here — a caller must not be able to
/// inject a "verification" row that no verification produced, which would let
/// them forge an approval into the audit trail.
async fn lifecycle_event(
    State(state): State<AppState>,
    payload: Result<Json<LifecycleEventBody>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Json(body) = payload.map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": e.body_text(),
                "error_type": "JsonRejection",
            })),
        )
    })?;

    if body.event_type.is_self_observed() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "this event type is emitted by Graphite itself and cannot be reported by a caller",
                "hint": "only signing, submission, confirmation and finalization are caller-reported",
            })),
        ));
    }
    let content_hash = body.content_hash.trim().to_string();
    if content_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "content_hash is required — it links this event to the verification that approved the transaction",
            })),
        ));
    }
    // Every field of this body lands on the audit volume. The shape checks
    // refuse what cannot be the thing it claims to be — a content_hash is 16
    // lowercase hex characters, a signature at most 88 base58 characters —
    // and the length caps bound the free-form ones, reporting lengths and
    // never values, so the rejection cannot amplify (Round 9; the same rule
    // `/verify` has applied to its identifiers since 2026-09-06).
    if content_hash.len() != 16
        || !content_hash
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "content_hash is {} characters; a Graphite content_hash is 16 lowercase hexadecimal characters",
                    content_hash.len()
                ),
            })),
        ));
    }
    for (name, value, max) in [
        (
            "audit_trail_id",
            body.audit_trail_id.as_deref(),
            MAX_LIFECYCLE_ID_CHARS,
        ),
        (
            "transaction_signature",
            body.transaction_signature.as_deref(),
            MAX_SIGNATURE_CHARS,
        ),
        (
            "reported_by",
            body.reported_by.as_deref(),
            MAX_LIFECYCLE_ID_CHARS,
        ),
        ("detail", body.detail.as_deref(), MAX_LIFECYCLE_DETAIL_CHARS),
    ] {
        if let Some(v) = value {
            let n = v.chars().count();
            if n > max {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("{name} is {n} characters; the maximum is {max}"),
                    })),
                ));
            }
        }
    }

    // A signature, when given, has to be one; and from submission onward
    // an attestation without one names no execution at all (Round 12).
    let transaction_signature = body
        .transaction_signature
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if let Some(sig) = &transaction_signature {
        if let Err(why) = signature_shape(sig) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("transaction_signature: {why}") })),
            ));
        }
    }
    if transaction_signature.is_none()
        && matches!(
            body.event_type,
            LifecycleEvent::Submission
                | LifecycleEvent::Confirmation
                | LifecycleEvent::Finalization
        )
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "a {:?} event needs transaction_signature: from submission onward the signature is the execution's identity, and an attestation without it can never be reconciled by L8",
                    body.event_type
                ),
            })),
        ));
    }

    let Some(log) = &state.audit else {
        // Durability is a P9 guarantee; accepting an event we cannot persist
        // would silently lose it.
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "audit log unavailable — the event was NOT recorded",
            })),
        ));
    };

    // The one fact about this attestation Graphite can establish itself:
    // what the trail says about the verification it names. Resolved by the
    // most exact key supplied — `audit_trail_id`, else `transaction_sha256`,
    // else `content_hash` — and never by a coarser one when the exact one
    // finds nothing (a spoofed id must not be rescued by a real hash). The
    // keys the caller supplied must agree with each other on the record
    // found; a row whose keys name two different verifications is a
    // malformed attestation and is refused rather than recorded. Recorded
    // on the row with the key that resolved it, returned to the caller,
    // counted — and, for a report against a BLOCKED verdict, logged as
    // loudly as an L8 discrepancy, because it is one (Round 9 / Round 10).
    let transaction_sha256 = body
        .transaction_sha256
        .as_deref()
        .map(str::trim)
        .map(String::from);
    if let Some(t) = &transaction_sha256 {
        if !is_sha256_hex(t) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "transaction_sha256 is {} characters; a SHA-256 is 64 lowercase hexadecimal characters",
                        t.len()
                    ),
                })),
            ));
        }
    }
    let audit_trail_id = body
        .audit_trail_id
        .as_deref()
        .map(str::trim)
        .map(String::from);
    // On the blocking pool (Round 19, F-19-18): an unknown key is looked up
    // through every archive.
    let (found, verdict_on_record_key) = {
        let log = log.clone();
        let audit_trail_id = audit_trail_id.clone();
        let transaction_sha256 = transaction_sha256.clone();
        let content_hash = content_hash.clone();
        crate::verification::bounded_archive_scan(move || {
            if let Some(id) = &audit_trail_id {
                (
                    log.find_verification(VerificationKey::AuditTrailId(id)),
                    VerificationKeyKind::AuditTrailId,
                )
            } else if let Some(t) = &transaction_sha256 {
                (
                    log.find_verification(VerificationKey::TransactionSha256(t)),
                    VerificationKeyKind::TransactionSha256,
                )
            } else {
                (
                    log.find_verification(VerificationKey::ContentHash(&content_hash)),
                    VerificationKeyKind::ContentHash,
                )
            }
        })
        .await
        .map_err(|join| {
            tracing_server_error(&format!("audit lookup did not complete: {join}"));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal server error" })),
            )
        })?
    };
    if let Some(r) = &found {
        let mut disagree = Vec::new();
        if r.content_hash != content_hash {
            disagree.push(format!(
                "content_hash {content_hash} was supplied but that verification's content_hash is {}",
                r.content_hash
            ));
        }
        if let Some(t) = &transaction_sha256 {
            if r.transaction_sha256.as_deref() != Some(t.as_str()) {
                disagree.push(format!(
                    "transaction_sha256 {t} was supplied but that verification's is {}",
                    r.transaction_sha256
                        .as_deref()
                        .unwrap_or("absent (descriptive)")
                ));
            }
        }
        if !disagree.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "the keys on this event name different verifications — refusing to record an attestation that contradicts itself",
                    "error_type": "InconsistentKeys",
                    "detail": disagree,
                    "resolved_by": verdict_on_record_key,
                })),
            ));
        }
    }
    let verdict_on_record = match &found {
        Some(r) if r.approved => VerdictOnRecord::Approved,
        Some(_) => VerdictOnRecord::Blocked,
        None => VerdictOnRecord::NotFound,
    };
    match verdict_on_record {
        VerdictOnRecord::Blocked => {
            Metrics::inc(&state.metrics.lifecycle_on_blocked);
            tracing_server_error(&format!(
                "LIFECYCLE REPORT ON A BLOCKED VERDICT: {:?} reported by {:?} for content_hash {} which Graphite BLOCKED — the gate's decision did not govern the wallet",
                body.event_type,
                body.reported_by.as_deref().unwrap_or("<unnamed>"),
                content_hash
            ));
        }
        VerdictOnRecord::NotFound => {
            Metrics::inc(&state.metrics.lifecycle_unverified);
            tracing_log(&format!(
                "lifecycle {:?} reported for content_hash {} with no verification on record",
                body.event_type, content_hash
            ));
        }
        VerdictOnRecord::Approved => {}
    }

    // A4-11 (2026-09-29 audit): the history read and the append are one
    // step. Two reports arriving together each read a history without the
    // other and were both recorded, so two different signatures for one
    // transaction carried no `signature conflict`. Lifecycle reports are few;
    // they are taken one at a time.
    //
    // The read, the comparison and the append run in ONE blocking task that
    // holds the lock throughout (review of that fix, F9). With an async lock
    // around separate awaits, a request cancelled by the timeout released
    // the lock while its append was still running on the blocking pool, and
    // the race was back. A blocking task runs to completion whatever happens
    // to the request that started it, so its lock is held until the row is
    // written.
    //
    // The rows already on record for this transaction, and how this one
    // sits against them (Round 12), are computed by Graphite from its own
    // trail; recorded on the row and returned, never used to refuse — a
    // report out of order is still a report — except that the two findings
    // that mean a report is FALSE are logged as loudly as a discrepancy,
    // because one of the two reports must be.
    static LIFECYCLE_REPORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let (prior_events_on_record, record, recorded) = {
        let log = log.clone();
        let event_type = body.event_type;
        let reported_by = body.reported_by;
        let detail = body.detail;
        off_runtime(move || {
            let _one_report_at_a_time = match LIFECYCLE_REPORTS.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let history = log.lifecycle_history(crate::durable::LifecycleKey {
                audit_trail_id: audit_trail_id.as_deref(),
                transaction_sha256: transaction_sha256.as_deref(),
                transaction_signature: transaction_signature.as_deref(),
            });
            // Tests only: hold the window between the history read and the
            // append open for one dedicated trail id, so a test can show the
            // lock above is what closes it. Without this the race needs a
            // read to land in the microseconds before another report's
            // append, and the test passed with the lock removed (break B54
            // of the 2026-09-29 audit's campaign).
            #[cfg(test)]
            if audit_trail_id.as_deref() == Some(RACE_WINDOW_TRAIL_ID) {
                std::thread::sleep(std::time::Duration::from_millis(40));
            }
            let sequence_anomalies = lifecycle_sequence_anomalies(
                event_type,
                transaction_signature.as_deref(),
                &history,
            );
            let record = LifecycleEventRecord {
                event_type,
                timestamp: crate::durable::now_utc_rfc3339(),
                content_hash,
                verdict_on_record: Some(verdict_on_record),
                verdict_on_record_key: Some(verdict_on_record_key),
                transaction_sha256,
                audit_trail_id,
                transaction_signature,
                reported_by,
                detail,
                observed_by_graphite: false,
                sequence_anomalies,
            };
            let recorded = log.append_lifecycle(&record);
            (history.len(), record, recorded)
        })
        .await
    };
    if !record.sequence_anomalies.is_empty() {
        Metrics::inc(&state.metrics.lifecycle_sequence_anomalies);
        let loud = record
            .sequence_anomalies
            .iter()
            .any(|a| a.starts_with("signature conflict"));
        let line = format!(
            "LIFECYCLE SEQUENCE: {:?} reported by {:?} for {} — {}",
            record.event_type,
            record.reported_by.as_deref().unwrap_or("<unnamed>"),
            record
                .audit_trail_id
                .as_deref()
                .or(record.transaction_sha256.as_deref())
                .or(record.transaction_signature.as_deref())
                .unwrap_or(&record.content_hash),
            record.sequence_anomalies.join("; ")
        );
        if loud {
            tracing_server_error(&line);
        } else {
            tracing_log(&line);
        }
    }
    if !recorded {
        // `recorded: true` is the one thing this endpoint promises. When the
        // append fails the promise cannot be made, and the caller — which is
        // reporting a signing or submission it already performed — must know
        // to retry or to escalate. Previously an `assert!`, i.e. a panic and
        // an opaque 500.
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "audit write failed — the event was NOT recorded",
                "error_type": "AuditUnavailable",
                "event_type": record.event_type,
                "content_hash": record.content_hash,
            })),
        ));
    }
    Metrics::inc(&state.metrics.lifecycle_events);

    Ok(Json(serde_json::json!({
        "recorded": true,
        "event_type": record.event_type,
        "content_hash": record.content_hash,
        "verdict_on_record": verdict_on_record,
        "verdict_on_record_key": verdict_on_record_key,
        "sequence_anomalies": record.sequence_anomalies,
        "prior_events_on_record": prior_events_on_record,
    })))
}

/// The lifecycle order a transaction's caller-reported events follow.
fn lifecycle_rank(event: LifecycleEvent) -> Option<u8> {
    match event {
        LifecycleEvent::Signing => Some(1),
        LifecycleEvent::Submission => Some(2),
        LifecycleEvent::Confirmation => Some(3),
        LifecycleEvent::Finalization => Some(4),
        _ => None,
    }
}

/// How a new lifecycle report sits against the rows already on record for
/// the same transaction (Round 12).
///
/// Four findings, each a sentence a reader can act on:
///
/// - `duplicate`: the same stage was already reported with the same
///   signature. Expected from a retry — a bridge that did not hear the
///   first answer reports again — and harmless on the trail; named so a
///   reader does not count two submissions.
/// - `out of order`: a stage reported after a later one is already on
///   record (a signing after the submission, a submission after the
///   confirmation).
/// - `unpreceded`: a stage whose predecessor was never reported (a
///   confirmation with no submission on record). Attestations are
///   independent, so this is not refused; it is a gap in the account.
/// - `signature conflict`: a different signature is already attached to
///   this transaction. The exact artifact under the same signer set has
///   exactly one ed25519 signature, so one of the two reports is not
///   about this transaction. Logged as loudly as an L8 discrepancy.
///
/// Graphite's own L8 rows count for ordering (a confirmation Graphite
/// observed is a confirmation) but never as a duplicate of a caller's
/// report.
fn lifecycle_sequence_anomalies(
    event: LifecycleEvent,
    signature: Option<&str>,
    history: &[LifecycleEventRecord],
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(rank) = lifecycle_rank(event) else {
        return out;
    };
    if let Some(sig) = signature {
        if let Some(prior) = history.iter().find(|r| {
            r.transaction_signature
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s != sig)
        }) {
            out.push(format!(
                "signature conflict: {} is already on record for this transaction ({:?} at {}); a transaction has one signature, so one of the two reports is not about it",
                prior.transaction_signature.as_deref().unwrap_or(""),
                prior.event_type,
                prior.timestamp
            ));
        }
    }
    if let Some(prior) = history.iter().find(|r| {
        !r.observed_by_graphite
            && r.event_type == event
            && r.transaction_signature.as_deref() == signature
    }) {
        out.push(format!(
            "duplicate: {:?} was already reported at {} by {}",
            event,
            prior.timestamp,
            prior.reported_by.as_deref().unwrap_or("<unnamed>")
        ));
    }
    let later = history
        .iter()
        .filter(|r| lifecycle_rank(r.event_type).is_some_and(|k| k > rank))
        .min_by_key(|r| lifecycle_rank(r.event_type));
    if let Some(prior) = later {
        out.push(format!(
            "out of order: {:?} reported after a {:?} was already on record at {}",
            event, prior.event_type, prior.timestamp
        ));
    }
    if rank > 1 {
        let has_predecessor = history
            .iter()
            .any(|r| lifecycle_rank(r.event_type).is_some_and(|k| k == rank - 1));
        if !has_predecessor {
            let predecessor = match event {
                LifecycleEvent::Submission => "signing",
                LifecycleEvent::Confirmation => "submission",
                _ => "confirmation",
            };
            out.push(format!(
                "unpreceded: {:?} reported with no {predecessor} on record for this transaction",
                event
            ));
        }
    }
    out
}

async fn manifests_handler(State(state): State<AppState>) -> Response {
    // Serialized straight from the registry's references into the response
    // body: cloning every manifest per request, then serializing the copy,
    // was most of this endpoint's cost.
    match serde_json::to_vec(&state.core.list_manifests()) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing_server_error(&format!("manifests: serialization failed: {e}"));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "manifests could not be serialized" })),
            )
                .into_response()
        }
    }
}

/// Append a verification record on the blocking pool.
///
/// Every append ends in `sync_data`, a device flush that takes from
/// microseconds on NVMe to tens of milliseconds on a network disk. Made on
/// the async runtime, each one held a worker for that long, so under load
/// the flushes of concurrent verdicts stalled every other request on the
/// node, `/health` included, and throughput was bounded by the worker count
/// divided by the flush time. On the blocking pool a flush holds only its
/// own request. The durability contract is unchanged: the verdict is not
/// answered until the record is on disk.
async fn append_off_runtime(log: &AuditLog, record: AuditRecord) -> bool {
    let log = log.clone();
    off_runtime(move || log.append(&record)).await
}

/// [`append_off_runtime`] for an error-path record.
async fn append_error_off_runtime(log: &AuditLog, record: AuditErrorRecord) -> bool {
    let log = log.clone();
    off_runtime(move || log.append_error(&record)).await
}

/// [`append_off_runtime`] for a lifecycle event.
async fn append_lifecycle_off_runtime(log: &AuditLog, record: LifecycleEventRecord) -> bool {
    let log = log.clone();
    off_runtime(move || log.append_lifecycle(&record)).await
}

#[cfg(test)]
/// The most dashboard scans that run at once: they share
/// `verification::MAX_CONCURRENT_ARCHIVE_SCANS` with the lookups. Each
/// parses the audit file on the blocking pool, which the audit appends of
/// `/verify` also use; unbounded, a burst of dashboard polls queued every
/// verdict's write behind them (review of the 2026-09-29 audit's fix, F9).
const MAX_CONCURRENT_DASHBOARD_SCANS: usize = crate::verification::MAX_CONCURRENT_ARCHIVE_SCANS;

/// [`off_runtime`] for a dashboard scan, at most
/// [`MAX_CONCURRENT_DASHBOARD_SCANS`] at a time, the slot held until the scan
/// ends even when the request was abandoned (W21).
async fn dashboard_scan<T, F>(scan: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match crate::verification::bounded_archive_scan(scan).await {
        Ok(v) => v,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => panic!("an audit-trail scan did not complete: {join}"),
    }
}

/// Run a scan of the audit trail on the blocking pool (A4-04, 2026-09-29
/// audit). The dashboard's `/api/*` reads parse the audit file; on the async
/// runtime each held a worker for as long as the parse took, and a few polls
/// against a large trail stalled `/verify` and `/health` with it — the class
/// Round 19 (F-19-18) fixed for L8's lookups. A panic in the scan is
/// re-raised so the handler answers 500, never a partial view.
async fn off_runtime<T, F>(scan: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(scan).await {
        Ok(v) => v,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => panic!("an audit-trail scan did not complete: {join}"),
    }
}

/// Dashboard: Semantic Graph read-only snapshot (P4 — never mutates).
async fn graph_handler(State(state): State<AppState>) -> Json<crate::verification::GraphSnapshot> {
    Json(state.core.graph_snapshot())
}

/// Dashboard: confidence scores over time, from the audit log
/// (most recent first; the dashboard polls this for the time series).
async fn confidence_history_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Bounded read: the chart needs the most recent points; memory stays
    // bounded by the cap while `count` reports the exact total (P4 — the
    // dashboard is observability). The scan is O(log) per poll, which is
    // fine at the dashboard's cadence on a single core node.
    let audit = state.audit.clone();
    let (records, _, total, _) = dashboard_scan(move || match &audit {
        Some(log) => log.read_tail_filtered(CONFIDENCE_SERIES_CAP, AuditSelector::All),
        None => (Vec::new(), Vec::new(), 0, 0),
    })
    .await;
    let series: Vec<serde_json::Value> = records
        .iter()
        .rev()
        .map(|r| {
            // W22 (external review): what the verdict is bound to. Without
            // it the dashboard showed an approval of a description and an
            // approval of bytes the same way.
            serde_json::json!({
                "timestamp": r.timestamp,
                "confidence": r.confidence,
                "approved": r.approved,
                // Round 30: null on rows written before the decision existed
                // ("not reported", never read as either answer).
                "decision": r.decision,
                "executable": r.executable,
                "program_id": r.program_id,
                "audit_trail_id": r.audit_trail_id,
                "transaction_sha256": r.transaction_sha256,
                "manifest_version": r.manifest_version,
            })
        })
        .collect();
    Json(serde_json::json!({ "series": series, "count": total }))
}

/// Dashboard: policy-engine blocked transactions from the audit log
/// (most recent first). A violation is any record where the policy or risk
/// layer rejected the transaction.
async fn policy_violations_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Bounded read: only the most recent violations are surfaced; memory
    // stays bounded by the cap while `count` reports the exact total.
    let audit = state.audit.clone();
    let (records, errors, total_violations, total_errors) = dashboard_scan(move || match &audit {
        Some(log) => log.read_tail_filtered(VIOLATIONS_CAP, AuditSelector::Blocked),
        None => (Vec::new(), Vec::new(), 0, 0),
    })
    .await;
    let violations: Vec<serde_json::Value> = records
        .iter()
        .rev()
        .map(|r| {
            serde_json::json!({
                "timestamp": r.timestamp,
                "program_id": r.program_id,
                "protocol_name": r.protocol_name,
                "instruction_name": r.instruction_name,
                "confidence": r.confidence,
                "policy_verdict": r.policy_verdict,
                "risk_status": r.risk_status,
                "decision": r.decision,
                "executable": r.executable,
                "audit_trail_id": r.audit_trail_id,
                "transaction_sha256": r.transaction_sha256,
                "manifest_version": r.manifest_version,
            })
        })
        .collect();
    // Error-path probes (malformed/oversized/bad-input requests) are
    // violations of the protocol contract too — surface them so blocked
    // traffic is fully observable.
    let error_violations: Vec<serde_json::Value> = errors
        .iter()
        .rev()
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "program_id": e.program_id,
                "instruction_name": e.instruction_name,
                "error": e.error,
                "error_type": e.error_type,
                "status": e.status,
            })
        })
        .collect();
    // The true totals from the whole trail (audit 2026-10-20, L7): the error
    // half used the length of the capped list, so past VIOLATIONS_CAP error
    // records `count` stopped growing while the trail kept them.
    // Each half's true total as well, so the dashboard can show both without
    // reading a capped list's length as a total.
    Json(serde_json::json!({
        "violations": violations,
        "error_violations": error_violations,
        "violation_count": total_violations,
        "error_count": total_errors,
        "count": total_violations + total_errors,
    }))
}

/// The most rows `/api/protocols/top?limit=` returns.
const MAX_TOP_PROTOCOLS: usize = 500;
/// The rows `/api/protocols/top` returns without `?limit=`.
const DEFAULT_TOP_PROTOCOLS: usize = 5;

/// `?limit=` for `/api/protocols/top`: absent is the default of 5; otherwise
/// a whole number from 1 to [`MAX_TOP_PROTOCOLS`] (audit 2026-10-20: the
/// dashboard needs every program's verification count, and the fixed 5 rows
/// hid the rest).
fn top_protocols_limit(query: Option<&str>) -> Result<usize, String> {
    let mut limit = DEFAULT_TOP_PROTOCOLS;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "limit" {
            limit = value
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=MAX_TOP_PROTOCOLS).contains(n))
                .ok_or_else(|| {
                    format!("limit must be a whole number from 1 to {MAX_TOP_PROTOCOLS}")
                })?;
        }
    }
    Ok(limit)
}

/// Dashboard: the top protocols (5, or `?limit=` up to 500) by battle-tested
/// volume (operator-asserted evidence, P7) plus verified observation count from the
/// audit log. Sorted descending by volume; ties broken deterministically by
/// program id. `program_count` is how many programs there are in all.
async fn top_protocols_handler(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let limit = top_protocols_limit(query.as_deref()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e, "error_type": "InvalidInput" })),
        )
    })?;
    // Streaming per-program counts: memory is bounded by distinct programs,
    // never by log size.
    let audit = state.audit.clone();
    let observed = dashboard_scan(move || match &audit {
        Some(log) => log.observations_by_program(),
        None => std::collections::HashMap::new(),
    })
    .await;
    // One graph lock per request: the snapshot is owned data, so the guard
    // drops before the audit-log reads below (no nested locking).
    let snapshot = state.core.graph_snapshot();
    let mut rows: Vec<serde_json::Value> = snapshot
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "program_id": n.program_id,
                "name": n.name,
                "trust_tier": n.trust_tier,
                "battle_tested_tx_count": n.battle_tested_tx_count,
                "observed_verifications": observed.get(&n.program_id).copied().unwrap_or(0),
                "quarantined": n.quarantined,
            })
        })
        .collect();
    // Include programs observed via the audit log that have no graph node
    // (e.g. unknown programs that were verified and rejected).
    for (program_id, count) in &observed {
        if !snapshot.nodes.iter().any(|n| &n.program_id == program_id) {
            rows.push(serde_json::json!({
                "program_id": program_id,
                "name": program_id,
                "trust_tier": "Unknown",
                "battle_tested_tx_count": 0,
                "observed_verifications": count,
                "quarantined": false,
            }));
        }
    }
    // Descending by total volume (earned battle-tested tx + observed
    // verifications); ties broken by program id for determinism (P2).
    rows.sort_by(|a, b| {
        let total = |v: &serde_json::Value| -> u64 {
            v["battle_tested_tx_count"].as_u64().unwrap_or(0)
                + v["observed_verifications"].as_u64().unwrap_or(0)
        };
        total(b)
            .cmp(&total(a))
            .then_with(|| a["program_id"].as_str().cmp(&b["program_id"].as_str()))
    });
    let total = rows.len();
    rows.truncate(limit);
    Ok(Json(
        serde_json::json!({ "top": rows, "program_count": total }),
    ))
}

/// Dashboard: Manifest Registry state — accepted submissions with version
/// lineage, and registered reviewers (read-only view of the engine).
async fn registry_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let engine = &state.registry_engine;
    let records: Vec<serde_json::Value> = engine
        .records()
        .iter()
        .map(|r| {
            serde_json::json!({
                "program_id": r.program_id,
                "version_label": r.version_label,
                "previous_version_ref": r.previous_version_ref,
                "content_hash": r.content_hash,
                "trust_tier": r.trust_tier.as_str(),
                "source": r.source,
            })
        })
        .collect();
    let reviewers: Vec<serde_json::Value> = engine
        .reviewers()
        .iter()
        .map(|(pubkey, r)| {
            serde_json::json!({
                "pubkey": pubkey,
                "reputation_score": r.reputation_score,
            })
        })
        .collect();
    Json(serde_json::json!({
        "records": records,
        "reviewers": reviewers,
        "record_count": records.len(),
    }))
}

/// Emit an operational line through `tracing`, at INFO.
///
/// This was a bare `eprintln!`, which meant every operational line — including
/// the per-verification verdict lines, the most useful ones an operator has —
/// bypassed the subscriber entirely. Two consequences, both found by reading
/// the running container's logs on 2026-09-06:
///
///   - `GRAPHITE_LOG_FORMAT=json` installed a JSON subscriber and these lines
///     came out as plain text anyway, so the "structured logs for
///     Loki/ELK/Datadog" the compose file promises did not hold for the lines
///     an aggregator most needs to parse.
///   - `RUST_LOG` could neither raise nor suppress them.
fn tracing_log(msg: &str) {
    tracing::info!(target: "graphite", "{}", log_safe(msg));
}

/// A log line with every control character escaped (A4-12, 2026-09-29
/// audit). Server log lines interpolate caller-supplied fields — a program
/// id, a discriminator, an error message quoting them — and in the text log
/// format a newline in one of them wrote a second, forged log line. JSON
/// output escapes them itself; the text format did not. Escaped at the one
/// place every server line passes through, whatever the field.
fn log_safe(msg: &str) -> std::borrow::Cow<'_, str> {
    if msg.chars().any(char::is_control) {
        std::borrow::Cow::Owned(msg.chars().flat_map(char::escape_default).collect())
    } else {
        std::borrow::Cow::Borrowed(msg)
    }
}

/// A rejected request that the CALLER caused (malformed discriminator, bad
/// address, oversized body).
///
/// Deliberately WARN, not ERROR. Anyone who can reach the port can produce
/// these on demand, so logging them at ERROR hands an attacker a free lever on
/// the operator's alerting: fill the error stream with attacker-chosen noise
/// and bury the genuine server faults underneath it. The line is still emitted
/// — probing must leave a trail — and the audit record is written either way.
fn tracing_client_reject(msg: &str) {
    tracing::warn!(target: "graphite", "{}", log_safe(msg));
}

/// A fault on Graphite's side. Rare, actionable, and worth paging on — which
/// is only true while a caller cannot manufacture one.
fn tracing_server_error(msg: &str) {
    tracing::error!(target: "graphite", "{}", log_safe(msg));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_engine::WEAKEST_BUILTIN_MIN_CONFIDENCE;

    // ── X-Forwarded-For spoofing (HIGH, 2026-09-05 production audit) ────────
    //
    // The per-IP rate limiter is only as strong as its notion of "who is the
    // client". Before the fix, `client_ip` read the LEFTMOST `X-Forwarded-For`
    // entry — the one the CLIENT supplies — so an attacker rotated that header
    // per request, got a fresh token bucket every time, and the limiter became
    // a no-op. These tests are written from the attacker's side: each one is a
    // concrete spoofing attempt that must NOT succeed.

    fn req_with_xff(xff: Option<&str>) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder().uri("/verify");
        if let Some(v) = xff {
            b = b.header("x-forwarded-for", v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    const PEER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)), 9);

    /// F8 (review of the 2026-09-29 audit's fix): one peer holds at most its
    /// share of connections, a slot comes back when its connection ends, and
    /// an IPv6 /64 counts as one peer, as it does for the rate limiter.
    #[test]
    fn one_peer_cannot_hold_every_connection() {
        let peers = Arc::new(PeerConnections::default());
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "198.51.100.1".parse().unwrap();
        let first = peers.claim(a, 2).expect("first");
        let _second = peers.claim(a, 2).expect("second");
        assert_eq!(
            peers.claim(a, 2).err(),
            Some(PeerRefusal::Peer),
            "a third connection from one peer is refused"
        );
        assert!(peers.claim(b, 2).is_ok(), "another peer is unaffected");
        drop(first);
        assert!(
            peers.claim(a, 2).is_ok(),
            "a slot comes back when its connection ends"
        );

        let v6a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        let _x = peers.claim(v6a, 1).expect("first in the /64");
        assert_eq!(
            peers.claim(v6b, 1).err(),
            Some(PeerRefusal::Peer),
            "the same /64 is the same peer"
        );

        // 0 is no limit, and every slot is still returned: a peer with no
        // open connection leaves no entry behind.
        let held: Vec<_> = (0..100)
            .map(|_| peers.claim(b, 0).expect("unlimited"))
            .collect();
        assert_eq!(
            peers.lock().peers.get(&rate_limit_key(b)).copied(),
            Some(100)
        );
        drop(held);
        assert_eq!(peers.lock().peers.get(&rate_limit_key(b)).copied(), None);
    }

    /// Audit 2026-10-20 (L6): one IPv6 /56 is 256 /64s, and the per-/64 cap
    /// alone let its holder open 256 × the cap. The /48 a peer belongs to
    /// holds at most `SITE_CONNECTION_FACTOR` × the cap across all of its
    /// /64s; another /48 is unaffected, and site slots come back on drop.
    #[test]
    fn many_slash_64s_of_one_site_cannot_hold_every_connection() {
        let peers = Arc::new(PeerConnections::default());
        let cap = 2;
        // Distinct /64s inside one /56 (2001:db8:1:0000/56 .. 00ff).
        let held: Vec<_> = (0..SITE_CONNECTION_FACTOR * cap)
            .map(|i| {
                let ip: IpAddr = format!("2001:db8:1:{:x}::1", i % 256).parse().unwrap();
                peers.claim(ip, cap).expect("within the site's share")
            })
            .collect();
        let next: IpAddr = "2001:db8:1:ff::1".parse().unwrap();
        assert_eq!(
            peers.claim(next, cap).err(),
            Some(PeerRefusal::Site),
            "a fresh /64 of a /48 that already holds its share is refused"
        );
        let elsewhere: IpAddr = "2001:db8:2:ff::1".parse().unwrap();
        assert!(
            peers.claim(elsewhere, cap).is_ok(),
            "another /48 is unaffected"
        );
        // IPv4 has no site aggregate.
        assert!(site_key("203.0.113.7".parse().unwrap()).is_none());
        assert!(site_key("::ffff:203.0.113.7".parse().unwrap()).is_none());
        drop(held);
        assert!(peers.claim(next, cap).is_ok(), "site slots come back");
        assert_eq!(
            peers.lock().sites.len(),
            0,
            "no site entry is left once its connections end"
        );
    }

    /// Audit 2026-10-20 (L4): a refusal any client can cause is logged at
    /// most once per window, and the line carries how many were suppressed.
    #[test]
    fn refusal_logging_is_throttled_and_counts_what_it_suppressed() {
        let t = LogThrottle::new(60);
        assert_eq!(t.admit(), Some(0), "the first line is written");
        for _ in 0..5 {
            assert_eq!(t.admit(), None, "inside the window: suppressed");
        }
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(t.admit(), Some(5), "the next line reports the five");
        assert_eq!(t.admit(), None);
        assert_eq!(suppressed_note(0), "");
        assert!(suppressed_note(5).contains("5 more"));
    }

    /// A4-02: a second `X-Forwarded-For` LINE is part of the same list; the
    /// proxy-appended entry is the last one of all lines, never the first
    /// line's.
    #[test]
    fn a_second_xff_line_does_not_choose_the_bucket() {
        let req = axum::http::Request::builder()
            .uri("/verify")
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-forwarded-for", "198.51.100.42")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    /// An entry with a port names the same client (A4, 2026-09-29 audit):
    /// it keys that client's bucket, not the proxy's.
    #[test]
    fn an_xff_entry_with_a_port_keys_its_client() {
        let req = req_with_xff(Some("6.6.6.6, 198.51.100.42:4711"));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
        let req = req_with_xff(Some("[2001:db8::1]:443"));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    /// A4-12: a control character in a logged field cannot start a new line.
    #[test]
    fn log_lines_escape_control_characters() {
        let line = log_safe("verify: evil\nFAKE LINE\r\u{1b}[31m");
        assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'));
        assert!(matches!(
            log_safe("plain"),
            std::borrow::Cow::Borrowed("plain")
        ));
    }

    /// With no trusted proxy configured, the header must be ignored entirely —
    /// a directly-reachable server must never believe a caller-supplied IP.
    #[test]
    fn xff_is_ignored_when_no_proxy_is_trusted() {
        let req = req_with_xff(Some("1.2.3.4"));
        assert_eq!(client_ip(&req, PEER, 0), PEER.ip());
    }

    /// The canonical attack: nginx's `proxy_add_x_forwarded_for` APPENDS the
    /// real peer to whatever the client sent, so the header becomes
    /// `<attacker's claim>, <real client IP>`. Reading the left end returned
    /// the attacker's claim. With one trusted hop we must read the RIGHTMOST
    /// entry — the one our own proxy wrote.
    #[test]
    fn spoofed_leftmost_xff_entry_is_not_believed() {
        let req = req_with_xff(Some("6.6.6.6, 198.51.100.42"));
        let ip = client_ip(&req, PEER, 1);
        assert_eq!(
            ip,
            "198.51.100.42".parse::<IpAddr>().unwrap(),
            "must use the proxy-appended (rightmost) entry, not the client's claim"
        );
        assert_ne!(ip, "6.6.6.6".parse::<IpAddr>().unwrap());
    }

    /// Rotating the spoofed prefix must NOT produce different rate-limit
    /// identities — this is the actual bypass, stated as a property: every
    /// request from one real client must map to one bucket key regardless of
    /// what the client puts in the header.
    #[test]
    fn rotating_spoofed_xff_prefixes_cannot_rotate_the_rate_limit_identity() {
        let attacker_claims = [
            "1.1.1.1",
            "9.9.9.9",
            "8.8.8.8, 7.7.7.7",
            "203.0.113.99, 10.0.0.1, 172.16.0.9",
        ];
        let resolved: Vec<IpAddr> = attacker_claims
            .iter()
            .map(|claim| {
                let header = format!("{claim}, 198.51.100.42");
                client_ip(&req_with_xff(Some(&header)), PEER, 1)
            })
            .collect();

        let real = "198.51.100.42".parse::<IpAddr>().unwrap();
        assert!(
            resolved.iter().all(|ip| *ip == real),
            "every spoofing attempt must collapse to the same real client identity, got {resolved:?}"
        );
    }

    /// Two trusted proxies: the real client is the entry immediately left of
    /// the two our infrastructure appended.
    #[test]
    fn multiple_trusted_hops_index_from_the_right() {
        // <spoofed>, <real client>, <proxy-1 saw>, appended by proxy-2
        let req = req_with_xff(Some("6.6.6.6, 198.51.100.42, 10.0.0.1"));
        assert_eq!(
            client_ip(&req, PEER, 2),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    /// A request that did NOT traverse the expected proxy chain (fewer
    /// entries than configured hops) must never have a partial chain
    /// trusted: otherwise an attacker who can reach the server directly,
    /// bypassing the proxy, sends a single-entry header and picks their own
    /// identity. It keys the shared unattributed bucket, not the peer's:
    /// behind a proxy the peer IS the proxy (audit 2026-10-20, L1).
    #[test]
    fn short_xff_chain_is_not_trusted() {
        let req = req_with_xff(Some("6.6.6.6"));
        let ip = client_ip(&req, PEER, 2);
        assert_eq!(
            ip, UNATTRIBUTED_CLIENT,
            "a chain shorter than the trusted hop count must not be believed"
        );
        assert_ne!(ip, "6.6.6.6".parse::<IpAddr>().unwrap());
    }

    /// Malformed, empty, and garbage headers must not panic, must not be
    /// believed, and must not land in the peer's (behind a proxy: the
    /// proxy's) bucket: they share the one unattributed key. No header at
    /// all is a direct client or the proxy's own request, keyed by the peer.
    #[test]
    fn malformed_xff_headers_key_the_unattributed_bucket() {
        for header in ["", "   ", ",,,", "not-an-ip", "999.999.999.999", ", ,"] {
            assert_eq!(
                client_ip(&req_with_xff(Some(header)), PEER, 1),
                UNATTRIBUTED_CLIENT,
                "malformed header {header:?} must key the unattributed bucket"
            );
        }
        assert_eq!(client_ip(&req_with_xff(None), PEER, 1), PEER.ip());
        // The key survives rate-limit masking and is no peer's address.
        assert_eq!(rate_limit_key(UNATTRIBUTED_CLIENT), UNATTRIBUTED_CLIENT);
        assert_ne!(UNATTRIBUTED_CLIENT, PEER.ip());
    }

    /// Audit 2026-10-20 (L1): a byte that is not visible ASCII in the
    /// client's OWN part of the chain made the whole header unreadable and
    /// keyed the request by the peer — the proxy — so any client could move
    /// its requests into the bucket the proxy's own traffic uses and drain
    /// it. Only the entry at the client's position is read; whatever the
    /// client put to its left is never parsed.
    #[test]
    fn a_non_ascii_client_entry_does_not_move_the_request_to_the_proxys_bucket() {
        let lines: [&[u8]; 2] = [b"\xff\xfe junk \xc3\xa9", b"198.51.100.42"];
        let mut b = axum::http::Request::builder().uri("/verify");
        for line in lines {
            b = b.header(
                "x-forwarded-for",
                HeaderValue::from_bytes(line).expect("obs-text is a valid header value"),
            );
        }
        let req = b.body(axum::body::Body::empty()).unwrap();
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.42".parse::<IpAddr>().unwrap(),
            "the proxy-appended entry names the client whatever the client's own line holds"
        );
        // One line: the client's junk, then the proxy's append.
        let req = axum::http::Request::builder()
            .uri("/verify")
            .header(
                "x-forwarded-for",
                HeaderValue::from_bytes(b"\xff\xff, 198.51.100.43").unwrap(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.43".parse::<IpAddr>().unwrap()
        );
        // The entry AT the client's position is malformed: unattributed,
        // never the proxy's address.
        let req = axum::http::Request::builder()
            .uri("/verify")
            .header(
                "x-forwarded-for",
                HeaderValue::from_bytes(b"198.51.100.44, \xff\xff").unwrap(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(client_ip(&req, PEER, 1), UNATTRIBUTED_CLIENT);
    }

    /// IPv6 entries (and the bracketed form proxies sometimes emit) must
    /// resolve correctly rather than silently falling back — a fallback here
    /// would collapse all IPv6 clients behind the proxy into one bucket.
    #[test]
    fn ipv6_xff_entries_resolve() {
        let req = req_with_xff(Some("6.6.6.6, 2001:db8::42"));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "2001:db8::42".parse::<IpAddr>().unwrap()
        );
    }

    /// Whitespace padding must not defeat parsing (proxies emit `a, b` with
    /// varying spacing) — a parse failure would fall back to the shared peer
    /// address and re-collapse every client into one bucket.
    #[test]
    fn whitespace_padded_entries_still_parse() {
        let req = req_with_xff(Some("6.6.6.6 ,   198.51.100.42   "));
        assert_eq!(
            client_ip(&req, PEER, 1),
            "198.51.100.42".parse::<IpAddr>().unwrap()
        );
    }

    /// FIFO eviction must keep the bucket map bounded: with a cap of 3,
    /// inserting a 4th distinct IP evicts the oldest-inserted one (O(1), no
    /// full-map sweep).
    /// Round 10 measurement: the limiter at its bound. One million distinct
    /// IPs inserted through the one mutex, then one million more that each
    /// evict the oldest. Reported, and bounded loosely: a full map must not
    /// turn `check` into something a caller could feel.
    #[test]
    fn rate_limiter_at_its_bound_stays_cheap_per_check() {
        let rl = RateLimiter::with_capacity(MAX_BUCKETS, 1000.0);
        let ip = |i: u32| IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2654435761)));
        let started = Instant::now();
        for i in 0..MAX_BUCKETS as u32 {
            assert!(rl.check(ip(i)));
        }
        let fill = started.elapsed();
        let started = Instant::now();
        for i in MAX_BUCKETS as u32..(2 * MAX_BUCKETS) as u32 {
            assert!(rl.check(ip(i)));
        }
        let churn = started.elapsed();
        let inner = rl.buckets.lock().unwrap();
        assert_eq!(inner.buckets.len(), MAX_BUCKETS, "bounded at the cap");
        let per_entry = std::mem::size_of::<IpAddr>()
            + std::mem::size_of::<Bucket>()
            + std::mem::size_of::<IpAddr>();
        println!(
            "round10: rate limiter — fill {} buckets: {:?} ({:.0} ns/check); churn {} evictions: {:?} ({:.0} ns/check); ~{} MB of entries plus map overhead",
            MAX_BUCKETS,
            fill,
            fill.as_nanos() as f64 / MAX_BUCKETS as f64,
            MAX_BUCKETS,
            churn,
            churn.as_nanos() as f64 / MAX_BUCKETS as f64,
            per_entry * MAX_BUCKETS / (1024 * 1024)
        );
        assert!(
            (churn.as_nanos() / MAX_BUCKETS as u128) < 5_000,
            "a check at capacity must stay under 5 µs: {churn:?}"
        );
    }

    #[test]
    fn rate_limiter_evicts_oldest_at_capacity() {
        let rl = RateLimiter::with_capacity(3, 1000.0); // huge refill rate: never tokens-starved
        let ips: Vec<IpAddr> = (0..6).map(|i| IpAddr::from([10, 0, 0, i as u8])).collect();

        for ip in &ips {
            assert!(
                rl.check(*ip),
                "all requests allowed under a huge refill rate"
            );
        }

        let inner = rl.buckets.lock().unwrap();
        assert!(
            inner.buckets.len() <= 3,
            "bucket map must stay bounded at the cap, got {}",
            inner.buckets.len()
        );
        // The first two IPs inserted must have been evicted (FIFO); the last
        // three remain.
        assert!(inner.buckets.contains_key(&ips[3]));
        assert!(inner.buckets.contains_key(&ips[4]));
        assert!(inner.buckets.contains_key(&ips[5]));
        assert!(!inner.buckets.contains_key(&ips[0]));
        assert!(!inner.buckets.contains_key(&ips[1]));
    }

    /// Per-IP limiting still holds with the FIFO ring in place: a client that
    /// exhausts its bucket is denied until the refill window passes.
    #[test]
    fn rate_limiter_denies_after_bucket_exhausted() {
        let rl = RateLimiter::with_capacity(8, 2.0); // 2 tokens/s
        let ip = IpAddr::from([10, 0, 0, 9]);
        // 2 allowed immediately (bucket starts full at 2 tokens), 3rd denied.
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
        // A different IP is unaffected.
        assert!(rl.check(IpAddr::from([10, 0, 0, 10])));
    }
    // ─── Dashboard read-only API (P4) ────────────────────────────────────────

    /// Build an app state with a seeded core + an audit log in a temp dir.
    /// Each call gets a unique dir (parallel tests must never share the audit
    /// file — appends from one test would leak into another's readout).
    pub(super) fn test_state() -> (AppState, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "graphite-dash-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut core =
            crate::verification::GraphiteCore::try_with_data_dir(dir.clone()).expect("data dir");
        // Earned evidence for the System Program (battle-tested tier + baseline).
        use crate::semantic_graph_store::{Behavior, BehaviorEvidence};
        use crate::simulation_integrity::ComputeBaseline;
        core.seed_behavior(Behavior {
            program_id: "11111111111111111111111111111111".to_string(),
            version: "1.0.0".to_string(),
            expected_state_changes: vec!["debits accounts.from by amount".to_string()],
            allowed_cpis: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()],
            trust_tier: crate::TrustTier::Unknown,
            evidence: BehaviorEvidence {
                has_signed_manifest: true,
                community_verified_count: 2,
                battle_tested_tx_count: 1500,
                simulation_match_count: 100,
            },
            quarantined: false,
            quarantine_reason: None,
        })
        .unwrap();
        core.seed_simulation_baseline(
            "11111111111111111111111111111111",
            ComputeBaseline {
                mean_compute_units: 150.0,
                std_compute_units: 1.0,
                sample_count: 50,
                mean_account_writes: 2.0,
                std_account_writes: 0.5,
                mean_cpi_hops: 0.0,
                std_cpi_hops: 0.1,
                ..Default::default()
            },
        )
        .unwrap();
        let audit = AuditLog::open(audit_path(&dir)).unwrap();
        let state = AppState {
            core: Arc::new(core),
            api_key: None,
            admin_key: None,
            read_key: None,
            audit: Some(audit),
            registry_engine: Arc::new(crate::manifest_registry::ManifestRegistryEngine::new()),
            rate: RateLimiter::new(1000.0),
            trust_proxy_hops: 0,
            metrics: Metrics::default(),
            // Test harness: a fixed, generous limit so shedding never masks the
            // behaviour under test. The shedding path has its own tests.
            inflight: Arc::new(tokio::sync::Semaphore::new(1024)),
            inflight_limit: 1024,
            aux_inflight: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_AUXILIARY)),
            pinned_profile: None,
            allow_permissive_profiles: false,
        };
        (state, dir)
    }

    /// A server whose in-flight limit is already fully consumed.
    ///
    /// Measured on the shipped container before this existed: 50 concurrent
    /// verifications against a live devnet RPC produced 33 answers and 17 bare
    /// `408`s over 26 seconds. A request that dies at REQUEST_TIMEOUT carries no
    /// verdict, no layer report and no audit record — under load, exactly when
    /// an operator most needs to know what the gate decided, Graphite went
    /// quiet. After: 32 answers and 18 immediate `503`s in 12 seconds.
    #[tokio::test]
    async fn a_saturated_server_sheds_with_503_and_retry_after_instead_of_expiring() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mut state, _dir) = test_state();
        // One permit, taken, so every request arrives at a full server.
        state.inflight = Arc::new(tokio::sync::Semaphore::new(1));
        state.inflight_limit = 1;
        let held = Arc::clone(&state.inflight).try_acquire_owned().unwrap();

        let shed_metric = Arc::clone(&state.metrics.load_shed);
        let app = build_app(state, vec![]);
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        // A verification: the route the permit is capacity for. (This used
        // `/health`, which no longer draws on the pool — audit 2026-10-20,
        // L3; see `health_is_neither_shed_nor_rate_limited`.)
        let verify = || {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        };
        let resp = app.clone().oneshot(verify()).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a saturated server must refuse immediately, not accept work it cannot finish"
        );
        // Retry-After is what makes the refusal actionable. A 408 told the
        // caller the server was slow at THEIR request, which invites an
        // immediate retry and deepens the overload.
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "a shed response must say when to come back"
        );
        assert_eq!(
            shed_metric.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "shedding must be visible in /metrics — an invisible refusal is an outage nobody can diagnose"
        );

        // And the server recovers the moment a permit is returned: shedding is
        // backpressure, not a latch.
        drop(held);
        let resp = app.oneshot(verify()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "the limit must be released when the request completes (the body `{{}}` reaches the handler and is refused there)"
        );
    }

    /// Audit 2026-10-20 (L3): `/health` is documented as open for load
    /// balancers, and it sat behind the rate limiter and the verification
    /// pool. A saturated node answered its balancer 503 and was pulled while
    /// it was merely busy; behind a trusted proxy every balancer probe keys
    /// the proxy's bucket. It is exempt from both, and stays cheap.
    #[tokio::test]
    async fn health_is_neither_shed_nor_rate_limited() {
        let (mut state, _dir) = test_state();
        state.inflight = Arc::new(tokio::sync::Semaphore::new(1));
        state.inflight_limit = 1;
        let _held = Arc::clone(&state.inflight).try_acquire_owned().unwrap();
        state.aux_inflight = Arc::new(tokio::sync::Semaphore::new(1));
        let _aux_held = Arc::clone(&state.aux_inflight).try_acquire_owned().unwrap();
        // A bucket of exactly one token that refills every ten seconds.
        state.rate = RateLimiter::new(0.1);
        let app = build_app(state, vec![]);
        for i in 0..5 {
            let (status, _) = get_text(&app, "/health").await;
            assert_eq!(
                status,
                StatusCode::OK,
                "/health #{i} was refused while the node was saturated and its caller over its rate"
            );
        }
        // The control: the same caller on another route is limited.
        let (first, _) = get_text(&app, "/manifests").await;
        let (second, _) = get_text(&app, "/manifests").await;
        assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE, "aux pool is full");
        assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    }

    /// Audit 2026-10-20 (M12): the dashboard's reads, `/manifests`,
    /// `/metrics`, lifecycle reports and operator actions held VERIFICATION
    /// permits while they waited on an archive-scan slot or the lifecycle
    /// lock, so slow dashboard polls shed `/verify`. They draw on their own
    /// pool: with every one of its slots held, a verification still runs,
    /// and with every verification permit held, the dashboard still reads.
    #[tokio::test]
    async fn non_verification_routes_cannot_hold_verification_permits() {
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let verify = || {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        };

        // Every non-verification slot held (32 slow dashboard polls).
        let (mut state, _dir) = test_state();
        state.aux_inflight = Arc::new(tokio::sync::Semaphore::new(2));
        let _polls = Arc::clone(&state.aux_inflight)
            .try_acquire_many_owned(2)
            .unwrap();
        let aux_shed = Arc::clone(&state.metrics.aux_load_shed);
        let verify_shed = Arc::clone(&state.metrics.load_shed);
        let app = build_app(state, vec![]);
        let resp = app.clone().oneshot(verify()).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "/verify must reach its handler while the dashboard pool is full"
        );
        let (status, body) = get_json(&app, "/api/policy-violations").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error_type"], "LoadShed");
        assert_eq!(aux_shed.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            verify_shed.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a dashboard shed is not a verification shed"
        );

        // Every verification permit held: the dashboard still answers.
        let (mut state, _dir) = test_state();
        state.inflight = Arc::new(tokio::sync::Semaphore::new(1));
        state.inflight_limit = 1;
        let _busy = Arc::clone(&state.inflight).try_acquire_owned().unwrap();
        let app = build_app(state, vec![]);
        for path in [
            "/api/graph",
            "/api/policy-violations",
            "/api/registry",
            "/metrics",
        ] {
            let (status, _) = get_text(&app, path).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{path} while verifications are saturated"
            );
        }
        let resp = app.oneshot(verify()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Shedding is distinct from rate limiting, and /metrics has to keep them
    /// apart: 429 means one caller is asking too often, 503 means the instance
    /// is saturated. An operator reads these to tell a noisy client from an
    /// undersized deployment.
    #[tokio::test]
    async fn shedding_and_rate_limiting_are_counted_separately() {
        let (state, _dir) = test_state();
        let app = build_app(state, vec![]);
        let (status, _) = get_text(&app, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = get_text(&app, "/metrics").await;
        assert!(
            body.contains("graphite_load_shed_total"),
            "the shed counter must be exported — an invisible refusal is an outage nobody can diagnose: {body}"
        );
        assert!(
            body.contains("graphite_rate_limited_total"),
            "the rate-limit counter must stay exported alongside it"
        );
    }

    #[test]
    fn the_quarantine_on_upgrade_flag_is_read_strictly() {
        for (v, want) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("false"), false),
            (Some("1"), true),
            (Some(" TRUE "), true),
        ] {
            assert_eq!(quarantine_on_upgrade_from(v), Ok(want), "{v:?}");
        }
        for v in ["yes", "on", "2", "ture"] {
            assert!(quarantine_on_upgrade_from(Some(v)).is_err(), "{v}");
        }
    }

    /// Roadmap R-M1: an operator sees how many programs were found upgraded,
    /// and whether an upgrade quarantines, on `/health` and in the metrics.
    #[tokio::test]
    async fn health_and_metrics_report_program_upgrades() {
        let (state, _dir) = test_state();
        let app = build_app(state, vec![]);
        let (status, health) = get_json(&app, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(health["program_upgrades"]["detected"], 0);
        assert_eq!(health["program_upgrades"]["quarantine_on_upgrade"], false);
        let (_, metrics) = get_text(&app, "/metrics").await;
        assert!(
            metrics.contains("graphite_program_upgrades_detected_total 0"),
            "{metrics}"
        );
    }

    /// Round 30 (G-01): a node without an RPC says on /health that every
    /// verdict it gives is analysis only, each /verify answer carries its
    /// decision, and the decision is on the trail and the dashboard series
    /// — null for a row written before it existed ("not reported").
    #[tokio::test]
    async fn the_decision_reaches_health_the_response_and_the_trail() {
        let (state, dir) = test_state();
        assert!(!state.core.has_rpc_client(), "test_state attaches no RPC");
        let log = state.audit.clone().unwrap();
        assert!(log.append(&AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: crate::durable::now_utc_rfc3339(),
            audit_trail_id: "gr-old".to_string(),
            content_hash: "h-old".to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: None,
            approved: true,
            decision: None,
            executable: None,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }));
        let app = build_app(state, vec![]);
        let (_, health) = get_json(&app, "/health").await;
        assert_eq!(health["verification_mode"], "analysis_only");
        assert_eq!(health["rpc_attached"], false);

        let input: serde_json::Value =
            serde_json::from_str(include_str!("../../examples/verify-input.json"))
                .expect("the committed example parses");
        let (status, body) = post_json(&app, "/verify", None, input).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["executable"], false, "no RPC: nothing is executable");
        let decision = body["decision"].as_str().expect("a decision").to_string();
        assert_ne!(decision, "executable_approved");
        assert_eq!(body["instruction_bind_key"], body["content_hash"]);

        let rows = log.read_tail_filtered(10, AuditSelector::All).0;
        let row = rows
            .iter()
            .find(|r| r.audit_trail_id == body["audit_trail_id"].as_str().unwrap())
            .expect("the verdict is on the trail");
        assert_eq!(row.decision.as_deref(), Some(decision.as_str()));
        assert_eq!(row.executable, Some(false));

        let (_, history) = get_json(&app, "/api/confidence-history").await;
        let series = history["series"].as_array().unwrap();
        assert_eq!(
            series[0]["decision"],
            decision.as_str(),
            "most recent first"
        );
        assert_eq!(series[0]["executable"], false);
        assert!(
            series[1]["decision"].is_null() && series[1]["executable"].is_null(),
            "a row from before Round 30 is not reported, never read as an answer: {}",
            series[1]
        );
        if decision == "blocked" {
            let (_, violations) = get_json(&app, "/api/policy-violations").await;
            assert_eq!(violations["violations"][0]["decision"], "blocked");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    async fn get_text(app: &Router, path: &str) -> (axum::http::StatusCode, String) {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn get_json(app: &Router, path: &str) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        // The rate-limit middleware reads ConnectInfo (provided by the real
        // listener via into_make_service_with_connect_info); oneshot tests
        // must inject it explicitly.
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// POST helper mirroring `get_json`.
    async fn post_json(
        app: &Router,
        path: &str,
        key: Option<&str>,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::Body;
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    // ─── Operator quarantine endpoint (ARCHITECTURE.md 3.8) ──────────────────

    /// An instance with no API key must refuse to expose the switch at all.
    /// Everywhere else an absent key means "dev mode"; here it would mean
    /// anyone who can reach the port can withdraw any program from trust.
    #[tokio::test]
    async fn quarantine_endpoint_is_refused_without_a_configured_api_key() {
        let (state, _dir) = test_state();
        assert!(state.api_key.is_none(), "test_state is unauthenticated");
        let app = build_app(state, vec![]);
        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            None,
            serde_json::json!({"program_id": SYSTEM, "reason": "test"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{json}");
    }

    const SYSTEM: &str = "11111111111111111111111111111111";

    /// A state with BOTH keys, returning the OPERATOR key (Round 19: the
    /// verify key no longer opens `/admin/*`).
    fn keyed_state() -> (AppState, std::path::PathBuf, String) {
        let (mut state, dir) = test_state();
        let key = "operator-test-key".to_string();
        state.api_key = Some(Arc::new(VERIFY_TEST_KEY.to_string()));
        state.admin_key = Some(Arc::new(key.clone()));
        (state, dir, key)
    }

    const VERIFY_TEST_KEY: &str = "verify-test-key";

    #[tokio::test]
    async fn quarantine_endpoint_blocks_the_program_and_persists_it() {
        let (state, dir, key) = keyed_state();
        let core = state.core.clone();
        let app = build_app(state, vec![]);

        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({
                "program_id": SYSTEM,
                "reason": "GHSA-2026-0001",
                "reported_by": "oncall@example.com",
            }),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{json}");
        assert_eq!(json["quarantined"], serde_json::json!(true));
        // The EARNED tier, which while quarantined is also the effective one.
        assert_eq!(json["earned_trust_tier"], serde_json::json!("Unknown"));

        // In force for this process...
        assert_eq!(
            core.quarantined_programs(),
            vec![(SYSTEM.to_string(), "GHSA-2026-0001".to_string())]
        );
        // ...and on disk, so a restart does not silently restore the program.
        let reloaded =
            crate::verification::GraphiteCore::try_with_data_dir(dir.clone()).expect("data dir");
        assert_eq!(reloaded.quarantined_programs().len(), 1);

        // Visible through the listing.
        let (status, listed) = {
            use axum::body::Body;
            use tower::ServiceExt;
            let mut req = axum::http::Request::builder()
                .uri("/admin/quarantine")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap();
            let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let resp = app.clone().oneshot(req).await.unwrap();
            let st = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                st,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        };
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(listed["count"], serde_json::json!(1));

        // Lifting works and empties the listing.
        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": SYSTEM, "lift": true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{json}");
        assert_eq!(json["quarantined"], serde_json::json!(false));
        assert!(core.quarantined_programs().is_empty());
    }

    /// W21 (external review, verified 2026-10-03): a quarantine stays in
    /// force when the trail cannot record it (undoing it would fail open), and
    /// a lift the trail cannot record is not applied, for the same reason.
    #[tokio::test]
    async fn a_quarantine_lift_the_trail_cannot_record_is_not_applied() {
        let (state, dir, key) = keyed_state();
        let core = state.core.clone();
        let log = state.audit.clone().unwrap();
        let app = build_app(state, vec![]);
        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": SYSTEM, "reason": "GHSA-2026-0002"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{json}");

        // Every append fails from here: a read-only handle in the log.
        {
            let ro = std::fs::OpenOptions::new()
                .read(true)
                .open(audit_path(&dir))
                .unwrap();
            *log.file.lock().unwrap() = ro;
        }
        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": SYSTEM, "lift": true}),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{json}"
        );
        assert_eq!(json["error_type"], "AuditUnavailable");
        assert_eq!(
            core.quarantined_programs(),
            vec![(SYSTEM.to_string(), "GHSA-2026-0002".to_string())],
            "the lift was not applied"
        );
        let reloaded =
            crate::verification::GraphiteCore::try_with_data_dir(dir.clone()).expect("data dir");
        assert_eq!(
            reloaded.quarantined_programs().len(),
            1,
            "nor persisted: a restart still has the quarantine"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn quarantine_endpoint_rejects_a_missing_reason_and_a_bogus_lift() {
        let (state, _dir, key) = keyed_state();
        let app = build_app(state, vec![]);

        // No reason: an unexplained withdrawal of trust is not auditable (P9).
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": SYSTEM}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        // Lifting something that is not quarantined.
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": SYSTEM, "lift": true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        // Empty program id.
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&key),
            serde_json::json!({"program_id": "  ", "reason": "x"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }

    /// Authenticated by default: every keyless combination that used to
    /// start now refuses, and the one that is allowed is named and bounded.
    ///
    /// Inverted 2026-09-12 from "unset key = dev mode". The old CLI guard
    /// only caught keyless + non-loopback; keyless + loopback started an
    /// unauthenticated server with nothing but a log line saying so.
    #[test]
    fn auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback() {
        let loopback: SocketAddr = "127.0.0.1:7331".parse().unwrap();
        let loopback6: SocketAddr = "[::1]:7331".parse().unwrap();
        let public: SocketAddr = "0.0.0.0:7331".parse().unwrap();
        let lan: SocketAddr = "192.168.1.10:7331".parse().unwrap();

        // A key wins everywhere, dev mode or not.
        let key = "k3y-k3y-k3y-k3y-k3y-k3y-k3y-k3y-";
        assert_eq!(key.len(), MIN_API_KEY_CHARS);
        for addr in [loopback, public, lan] {
            for dev in [false, true] {
                match auth_posture(addr, Some(key), dev) {
                    Ok(AuthPosture::ApiKey(k)) => assert_eq!(k.as_str(), key),
                    other => panic!("{addr} dev={dev}: expected ApiKey, got {other:?}"),
                }
            }
        }
        // Whitespace is not a key.
        assert!(auth_posture(loopback, Some("   "), false).is_err());
        assert!(auth_posture(loopback, Some(""), false).is_err());
        // Round 11: a short key is refused, on every address, with or without
        // dev mode — a weak key must not be rescued by a loopback bind.
        for addr in [loopback, public, lan] {
            for dev in [false, true] {
                let err = auth_posture(addr, Some("k3y"), dev).unwrap_err();
                assert!(err.contains("refusing to start"), "{err}");
                assert!(err.contains("32"), "{err}");
            }
        }
        assert!(auth_posture(loopback, Some(&key[..31]), false).is_err());

        // No key, no dev mode: refused on every address, including loopback —
        // the combination that used to start silently.
        for addr in [loopback, loopback6, public, lan] {
            let err = auth_posture(addr, None, false).unwrap_err();
            assert!(err.contains("GRAPHITE_DEV_MODE"), "{addr}: {err}");
            assert!(err.contains("refusing to start"), "{addr}: {err}");
        }

        // Dev mode: loopback only.
        assert_eq!(
            auth_posture(loopback, None, true).unwrap(),
            AuthPosture::DevModeLoopback
        );
        assert_eq!(
            auth_posture(loopback6, None, true).unwrap(),
            AuthPosture::DevModeLoopback
        );
        for addr in [public, lan] {
            let err = auth_posture(addr, None, true).unwrap_err();
            assert!(err.contains("loopback"), "{addr}: {err}");
            assert!(err.contains("refusing to bind"), "{addr}: {err}");
        }
    }

    /// The audit-append failure on `/audit/event` is a 503 that says "NOT
    /// recorded", not a panic. Reproduced by opening the log on a path whose
    /// directory is then removed, so the append genuinely fails.
    #[tokio::test]
    async fn lifecycle_event_reports_an_unrecorded_event_instead_of_panicking() {
        let dir = std::env::temp_dir().join(format!(
            "gr-lifecycle-503-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::open(dir.join("audit.jsonl")).unwrap();
        // Make the next append fail: on Windows an open file cannot be
        // deleted from under a handle without FILE_SHARE_DELETE, but Rust's
        // handles carry it; on every platform, removing the directory tree
        // and then writing works because the open handle keeps the inode —
        // so instead poison the log by swapping in a read-only handle.
        {
            let ro = std::fs::OpenOptions::new()
                .read(true)
                .open(dir.join("audit.jsonl"))
                .unwrap();
            let mut guard = log.file.lock().unwrap();
            *guard = ro;
        }
        let (mut state, state_dir) = test_state();
        state.audit = Some(log.clone());
        let app = build_app(state, Vec::new());
        let (status, body) = post_json(
            &app,
            "/audit/event",
            None,
            serde_json::json!({
                "event_type": "signing",
                "content_hash": "48c65c638aceb5de",
                "reported_by": "test",
            }),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error_type"], "AuditUnavailable");
        assert!(
            body["error"].as_str().unwrap().contains("NOT recorded"),
            "{body}"
        );
        assert!(
            body.get("recorded").is_none(),
            "no recorded:true on a failure"
        );
        assert_eq!(log.health().writes_failed, 1);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn quarantine_endpoint_requires_the_api_key_like_every_other_route() {
        let (state, _dir, _key) = keyed_state();
        let app = build_app(state, vec![]);
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some("wrong-key"),
            serde_json::json!({"program_id": SYSTEM, "reason": "x"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// Round 19 (F-19-13): the VERIFY key does not open the operator
    /// surface. It is the key an agent holds, and the agent is the party a
    /// quarantine protects against.
    #[tokio::test]
    async fn the_verify_key_cannot_lift_or_add_a_quarantine() {
        let (state, _dir, admin) = keyed_state();
        let core = state.core.clone();
        let app = build_app(state, vec![]);
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&admin),
            serde_json::json!({"program_id": SYSTEM, "reason": "GHSA-2026-0001"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "the operator key works");
        for body in [
            serde_json::json!({"program_id": SYSTEM, "lift": true}),
            serde_json::json!({"program_id": TOKEN_PROGRAM, "reason": "griefing"}),
        ] {
            let (status, json) =
                post_json(&app, "/admin/quarantine", Some(VERIFY_TEST_KEY), body).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{json}");
        }
        let still: Vec<String> = core
            .quarantined_programs()
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            still,
            vec![SYSTEM.to_string()],
            "nothing the verify key sent took effect"
        );
    }

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    /// Round 19 (F-19-13): without an operator key there is no operator
    /// surface, the verify key included.
    #[tokio::test]
    async fn without_an_operator_key_the_admin_surface_is_disabled() {
        let (mut state, _dir) = test_state();
        state.api_key = Some(Arc::new(VERIFY_TEST_KEY.to_string()));
        let app = build_app(state, vec![]);
        let (status, json) = post_json(
            &app,
            "/admin/quarantine",
            Some(VERIFY_TEST_KEY),
            serde_json::json!({"program_id": SYSTEM, "reason": "x"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{json}");
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("GRAPHITE_ADMIN_API_KEY"),
            "{json}"
        );
    }

    /// Round 19 (F-19-13): the operator key must be long and must not be the
    /// verify key.
    #[test]
    fn the_operator_key_is_refused_when_short_or_equal_to_the_verify_key() {
        let verify = "v".repeat(40);
        assert!(operator_key_posture(None, Some(&verify)).unwrap().is_none());
        assert!(operator_key_posture(Some("   "), Some(&verify))
            .unwrap()
            .is_none());
        assert!(operator_key_posture(Some("short"), Some(&verify)).is_err());
        let same = operator_key_posture(Some(&verify), Some(&verify)).unwrap_err();
        assert!(same.contains("equals GRAPHITE_API_KEY"), "{same}");
        let admin = "a".repeat(40);
        let got = operator_key_posture(Some(&admin), Some(&verify)).unwrap();
        assert_eq!(got.as_deref().map(String::as_str), Some(admin.as_str()));
    }

    /// Round 19 (F-19-15): the operator surface validates what it appends
    /// forever, and a repeat quarantine appends nothing.
    #[tokio::test]
    async fn quarantine_input_is_validated_and_idempotent() {
        let (state, _dir, admin) = keyed_state();
        let core = state.core.clone();
        let app = build_app(state, vec![]);
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&admin),
            serde_json::json!({"program_id": "not-a-program", "reason": "x"}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let (status, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&admin),
            serde_json::json!({
                "program_id": SYSTEM,
                "reason": "r".repeat(MAX_QUARANTINE_REASON_CHARS + 1),
            }),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        for _ in 0..3 {
            let (status, _) = post_json(
                &app,
                "/admin/quarantine",
                Some(&admin),
                serde_json::json!({"program_id": SYSTEM, "reason": "incident"}),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK);
        }
        let quarantine_records = core
            .behavior_history(SYSTEM)
            .into_iter()
            .filter(|b| b.quarantined)
            .count();
        assert_eq!(
            quarantine_records, 1,
            "three identical quarantines append one record"
        );
    }

    /// Round 19 (F-19-14): an unauthenticated client trickling a body cannot
    /// hold a verification permit. Served on a real loopback socket with ONE
    /// permit: while an unauthenticated request sits with half its body sent,
    /// the permit stays free, and the request is refused with 401.
    #[tokio::test]
    async fn an_unauthenticated_slow_body_does_not_hold_a_permit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut state, _dir) = test_state();
        state.api_key = Some(Arc::new(VERIFY_TEST_KEY.to_string()));
        state.inflight = Arc::new(tokio::sync::Semaphore::new(1));
        state.inflight_limit = 1;
        let inflight = state.inflight.clone();
        let app = build_app(state, vec![]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"POST /verify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"program_id\":",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            inflight.available_permits(),
            1,
            "the unauthenticated, unfinished request holds no permit"
        );
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the refusal arrives within the drain bound")
            .unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    }

    /// Round 19 (F-19-16): IPv6 clients share a bucket per /64; IPv4 per
    /// address; IPv4-mapped IPv6 is IPv4.
    #[test]
    fn rate_limit_keys_ipv6_by_slash_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(rate_limit_key(a), rate_limit_key(b));
        assert_ne!(rate_limit_key(a), rate_limit_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(
            rate_limit_key(mapped),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    /// Round 19 (F-19-16): a configured rate below 1 req/s still admits a
    /// request per bucket; it used to refuse every one.
    #[test]
    fn a_sub_one_rate_still_admits_requests() {
        let limiter = RateLimiter::new(0.5);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(limiter.check(ip), "the first request is admitted");
        assert!(!limiter.check(ip), "the second, immediately after, is not");
    }

    #[tokio::test]
    async fn dashboard_graph_endpoint_is_read_only_snapshot() {
        let (state, _dir) = test_state();
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/graph").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let nodes = json["nodes"].as_array().expect("nodes array");
        assert!(!nodes.is_empty(), "seed manifests must appear as nodes");
        // System Program node carries earned evidence.
        let sys = nodes
            .iter()
            .find(|n| n["program_id"] == "11111111111111111111111111111111")
            .expect("system node");
        assert_eq!(sys["battle_tested_tx_count"], 1500);
        assert_eq!(sys["baseline_samples"], 50);
        assert_eq!(sys["trust_tier"], "BattleTested");
        // CPI edges derived from allowed_cpis.
        let edges = json["edges"].as_array().unwrap();
        assert!(
            edges.iter().any(|e| {
                e["from"] == "11111111111111111111111111111111"
                    && e["to"] == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }),
            "CPI edge System -> Token must exist"
        );
    }

    #[tokio::test]
    async fn dashboard_confidence_history_reads_audit_log() {
        let (state, dir) = test_state();
        // Append two audit records directly (verification happened over HTTP).
        let log = state.audit.as_ref().unwrap();
        let ts = crate::durable::now_utc_rfc3339();
        assert!(log.append(&AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: ts.clone(),
            audit_trail_id: "gr-a".to_string(),
            content_hash: "h1".to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved: true,
            decision: None,
            executable: None,
            confidence: 0.9,
            risk_status: "Clear".to_string(),
            policy_verdict: "Approved".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }));
        assert!(log.append(&AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: ts,
            audit_trail_id: "gr-b".to_string(),
            content_hash: "h2".to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved: false,
            decision: None,
            executable: None,
            confidence: 0.3,
            risk_status: "Blocked".to_string(),
            policy_verdict: "RejectedBelowThreshold".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }));
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/confidence-history").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(json["count"], 2);
        let series = json["series"].as_array().unwrap();
        assert_eq!(series[0]["confidence"], 0.3, "most recent first");
        // W22: what each verdict is bound to travels with it.
        assert!(
            series[0]["transaction_sha256"].is_null(),
            "a descriptive verdict"
        );
        assert_eq!(series[0]["manifest_version"], "1.0.0");
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_policy_violations_lists_blocked_records() {
        let (state, dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        assert!(log.append(&AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: crate::durable::now_utc_rfc3339(),
            audit_trail_id: "gr-blocked".to_string(),
            content_hash: "h3".to_string(),
            transaction_sha256: None,
            program_id: "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M".to_string(),
            instruction_name: "openDca".to_string(),
            protocol_name: "Jupiter DCA".to_string(),
            manifest_version: None,
            approved: false,
            decision: None,
            executable: None,
            confidence: 0.4,
            risk_status: "Blocked".to_string(),
            policy_verdict: "RejectedRiskEngineBlock".to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }));
        // Error-path probe (malformed request) must surface as a violation too.
        assert!(log.append_error(&crate::durable::AuditErrorRecord {
            timestamp: crate::durable::now_utc_rfc3339(),
            program_id: "probe".to_string(),
            instruction_name: "n/a".to_string(),
            error: "missing proposed_intent".to_string(),
            error_type: "bad_input".to_string(),
            status: 400,
        }));
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/policy-violations").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        // count = blocked verifications + error-path probes (both surfaced).
        assert_eq!(json["count"], 2);
        assert_eq!(
            json["violations"][0]["program_id"],
            "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M"
        );
        assert_eq!(
            json["violations"][0]["policy_verdict"],
            "RejectedRiskEngineBlock"
        );
        // The error-path probe is surfaced separately, most recent first.
        assert_eq!(json["error_violations"][0]["program_id"], "probe");
        assert_eq!(json["error_violations"][0]["error_type"], "bad_input");
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_top_protocols_ranks_by_volume() {
        let (state, dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        // 3 verifications of the System program.
        for i in 0..3 {
            assert!(log.append(&AuditRecord {
                event_type: LifecycleEvent::Verification,
                timestamp: crate::durable::now_utc_rfc3339(),
                audit_trail_id: format!("gr-top-{i}"),
                content_hash: format!("h{i}"),
                transaction_sha256: None,
                program_id: "11111111111111111111111111111111".to_string(),
                instruction_name: "transfer".to_string(),
                protocol_name: "System Program".to_string(),
                manifest_version: None,
                approved: true,
                decision: None,
                executable: None,
                confidence: 0.9,
                risk_status: "Clear".to_string(),
                policy_verdict: "Approved".to_string(),
                l3_status: "inconclusive".to_string(),
                l8_status: "inconclusive".to_string(),
                wallet_profile: None,
            }));
        }
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/protocols/top").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let top = json["top"].as_array().unwrap();
        assert!(!top.is_empty() && top.len() <= 5, "top 5 protocols");
        // System Program (1500 battle-tested + 3 observed) must rank first.
        assert_eq!(top[0]["program_id"], "11111111111111111111111111111111");
        assert_eq!(top[0]["observed_verifications"], 3);
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_registry_returns_records_and_reviewers() {
        let (state, dir) = test_state();
        let mut engine = crate::manifest_registry::ManifestRegistryEngine::new();
        // A real ed25519 key: the registry refuses anything else (MR-6).
        let reviewer = bs58::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .into_string();
        engine.register_reviewer(&reviewer, 1000).unwrap();
        let mut state = state;
        state.registry_engine = Arc::new(engine);
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/registry").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(json["record_count"], 0, "no submissions yet (read-only)");
        assert_eq!(json["reviewers"][0]["pubkey"], reviewer.as_str());
        assert_eq!(json["reviewers"][0]["reputation_score"], 1000);
        let _ = dir;
    }

    #[tokio::test]
    async fn dashboard_endpoints_respect_api_key_auth() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri("/api/graph")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let _ = dir;
    }

    /// A 5xx must never echo internal error text to the caller. The detail
    /// belongs in the log and the audit record; the client gets a generic
    /// message plus a stable error CLASS it can branch on.
    ///
    /// Asserted at the classification boundary rather than by trying to
    /// provoke a specific internal failure over HTTP: the property under test
    /// is "Internal never discloses its payload", which is exactly what this
    /// checks, and it keeps holding as new internal error sources are added.
    #[test]
    fn internal_errors_never_disclose_their_detail_to_clients() {
        let secret = "connection string user=admin password=hunter2 at /srv/internal";
        let err = VerificationHttpError::Internal(secret.to_string());

        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !err.client_message().contains(secret),
            "internal detail leaked to the client: {}",
            err.client_message()
        );
        assert!(
            !err.client_message().contains("password"),
            "internal detail leaked to the client: {}",
            err.client_message()
        );
        // …but it is still available for the log line and audit record.
        assert!(
            err.message().contains(secret),
            "internal detail must remain available server-side for diagnosis"
        );

        // A 400 is caller-fixable input feedback and stays specific (P3).
        let bad = VerificationHttpError::BadRequest("Invalid address: xyz".to_string());
        assert_eq!(bad.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(bad.client_message(), "Invalid address: xyz");
    }

    /// `error_type` is returned to clients, so it must be the variant NAME
    /// only — `format!("{:?}", e)` renders the payload too and would leak the
    /// same internal detail the message redaction just removed.
    #[test]
    fn error_kind_exposes_only_the_variant_name() {
        let secret = "internal path /srv/graphite/secret";
        let e = VerificationError::TransactionBuild(secret.to_string());
        assert_eq!(error_kind(&e), "TransactionBuild");
        assert!(
            !error_kind(&e).contains(secret),
            "error_type must not carry the payload"
        );
        // Guard the actual regression: the Debug form (used for logs/audit)
        // DOES contain the payload, which is exactly why it must not be the
        // thing sent to clients.
        assert!(
            format!("{e:?}").contains(secret),
            "Debug is the detailed form — if this ever stops being true, the \
             log/audit path lost detail"
        );
    }

    // ── Malformed caller input must be a CLIENT error ───────────────────────
    //
    // Found live 2026-09-06 against the running container: a discriminator of
    // "zzzz", "abc", or anything else non-hex returned HTTP 500 and logged at
    // ERROR. It failed closed — nothing was ever approved — so this is not an
    // approval bypass. It is a free way for anyone who can reach the port to
    // manufacture 500s, trip SLO alerting, page an on-call rotation, and bury
    // genuine server errors in attacker-chosen noise.
    //
    // The cause was classification by substring: the matcher looked for
    // "invalid discriminator" while `transaction_builder` emitted "instruction
    // discriminator is invalid hex".

    /// Every `InstructionPlanError` variant, driven through the real
    /// `summarize_instruction` and the real classifier.
    ///
    /// This is the guard against the same drift returning. The builder consumes
    /// only the caller's plan, so each of these is a client error; if a future
    /// variant genuinely represents a server-side failure, this test fails and
    /// forces that to be a decision rather than an accident.
    #[test]
    fn every_transaction_builder_failure_is_a_client_error() {
        use crate::transaction_builder::{summarize_instruction, InstructionPlan};
        use crate::verification::VerificationError;

        let account = |a: &str| crate::account_resolution::ResolvedAccount {
            address: a.to_string(),
            role: "signer".to_string(),
            name: String::new(),
            is_pda: false,
            is_signer: true,
            is_writable: true,
            pda_seeds: vec![],
            identity: crate::account_resolution::AccountIdentity::Unverified,
            expected_address_mismatch: false,
            pda_mismatch: false,
            privilege_mismatch: false,
        };
        let ok_account = account("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
        let system = "11111111111111111111111111111111";

        let cases: Vec<(&str, InstructionPlan)> = vec![
            (
                "EmptyProgramId",
                InstructionPlan {
                    program_id: String::new(),
                    instruction_discriminator: "02000000".to_string(),
                    resolved_accounts: vec![ok_account.clone()],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
            (
                "MissingAccounts",
                InstructionPlan {
                    program_id: system.to_string(),
                    instruction_discriminator: "02000000".to_string(),
                    resolved_accounts: vec![],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
            (
                "InvalidDiscriminator (non-hex)",
                InstructionPlan {
                    program_id: system.to_string(),
                    instruction_discriminator: "zzzz".to_string(),
                    resolved_accounts: vec![ok_account.clone()],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
            (
                "InvalidDiscriminator (odd length)",
                InstructionPlan {
                    program_id: system.to_string(),
                    instruction_discriminator: "abc".to_string(),
                    resolved_accounts: vec![ok_account.clone()],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
            (
                "InvalidPubkey",
                InstructionPlan {
                    program_id: system.to_string(),
                    instruction_discriminator: "02000000".to_string(),
                    resolved_accounts: vec![account("not-a-valid-base58-pubkey!!")],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
            (
                "InvalidProgramId",
                InstructionPlan {
                    program_id: "OOO-not-base58".to_string(),
                    instruction_discriminator: "02000000".to_string(),
                    resolved_accounts: vec![ok_account.clone()],
                    protocol_version: "1.0.0".to_string(),
                    instruction_name: "Transfer".to_string(),
                    expected_state_changes: vec![],
                    allowed_cpis: vec![],
                    instruction_data: vec![],
                },
            ),
        ];

        for (label, plan) in cases {
            let err = summarize_instruction(&plan)
                .expect_err(&format!("{label}: the plan must not build"));
            let classified = classify_error(&VerificationError::TransactionBuild(err.to_string()));
            assert_eq!(
                classified.status_code(),
                StatusCode::BAD_REQUEST,
                "{label}: malformed caller input classified as {} — an attacker can manufacture that status for free. error: {err}",
                classified.status_code()
            );
        }
    }

    /// The specific regression, at the exact input that produced it.
    #[test]
    fn a_non_hex_discriminator_is_400_not_500() {
        use crate::verification::VerificationError;
        for msg in [
            "instruction discriminator is invalid hex: Invalid character 'z' at position 0",
            "instruction discriminator is invalid hex: Odd number of digits",
            "instruction discriminator is invalid hex: Invalid character ' ' at position 0",
        ] {
            let e = VerificationError::TransactionBuild(msg.to_string());
            assert_eq!(
                classify_error(&e).status_code(),
                StatusCode::BAD_REQUEST,
                "{msg}"
            );
        }
    }

    // ── Wallet-profile enforcement at the trust boundary ────────────────────
    //
    // CRITICAL (2026-09-05 red-team, verified live before the fix): sending
    // {"Custom":{"min_confidence":0.0,"min_trust_tier":"Unknown"}} approved a
    // transaction to a completely unmanifested program at confidence 0.0. The
    // P6 ceiling still computed correctly — it just stopped gating anything,
    // because the threshold it was compared against was attacker-chosen.

    use crate::confidence_engine::TrustTier;
    use crate::policy_engine::WalletProfile;

    /// The degenerate profile: the exact bypass, which must not survive.
    #[test]
    fn caller_supplied_profile_cannot_disable_the_confidence_gate() {
        let attack = WalletProfile::Custom {
            min_confidence: 0.0,
            min_trust_tier: TrustTier::Unknown,
        };
        let (effective, note) = enforce_wallet_profile(attack, None, false).unwrap();
        match effective {
            WalletProfile::Custom {
                min_confidence,
                min_trust_tier,
            } => {
                assert!(
                    min_confidence >= WEAKEST_BUILTIN_MIN_CONFIDENCE,
                    "a caller-chosen threshold below every built-in profile must be raised, got {min_confidence}"
                );
                // Round 17 (F-15-07): the tier axis is clamped too.
                assert!(
                    min_trust_tier >= crate::policy_engine::WEAKEST_BUILTIN_MIN_TRUST_TIER,
                    "the tier floor must be raised as well, got {min_trust_tier:?}"
                );
            }
            other => panic!("expected a clamped Custom profile, got {other:?}"),
        }
        assert!(
            note.is_some(),
            "the override must be disclosed, never applied silently (P3)"
        );
    }

    /// NaN, infinite and negative thresholds are not policies: refused as
    /// malformed in every mode — default, permissive and pinned (Round 19,
    /// F-19-27; until then they were clamped by default and passed through
    /// under GRAPHITE_ALLOW_PERMISSIVE_PROFILES).
    #[test]
    fn non_finite_or_negative_custom_thresholds_are_refused_in_every_mode() {
        for bad in [f64::NAN, f64::NEG_INFINITY, f64::INFINITY, -1.0, -0.0001] {
            for (pinned, permissive) in [
                (None, false),
                (None, true),
                (Some(WalletProfile::Treasury), false),
            ] {
                let r = enforce_wallet_profile(
                    WalletProfile::Custom {
                        min_confidence: bad,
                        min_trust_tier: TrustTier::Unknown,
                    },
                    pinned,
                    permissive,
                );
                assert!(
                    r.is_err(),
                    "threshold {bad} (pinned={pinned:?}, permissive={permissive}) must be refused: {r:?}"
                );
            }
        }
        // Exactly 0.0 is legal (the most permissive bar) and, by default,
        // is raised to the weakest built-in with the override disclosed.
        let (effective, note) = enforce_wallet_profile(
            WalletProfile::Custom {
                min_confidence: 0.0,
                min_trust_tier: TrustTier::Unknown,
            },
            None,
            false,
        )
        .unwrap();
        match effective {
            WalletProfile::Custom { min_confidence, .. } => {
                assert!(min_confidence >= WEAKEST_BUILTIN_MIN_CONFIDENCE)
            }
            other => panic!("expected Custom, got {other:?}"),
        }
        assert!(note.is_some());
    }

    /// A legitimately strict Custom profile must pass through untouched — the
    /// clamp raises a floor, it must never lower a ceiling.
    #[test]
    fn strict_custom_profiles_pass_through_unchanged() {
        let strict = WalletProfile::Custom {
            min_confidence: 0.97,
            min_trust_tier: TrustTier::BattleTested,
        };
        let (effective, note) = enforce_wallet_profile(strict, None, false).unwrap();
        assert_eq!(effective, strict);
        assert!(
            note.is_none(),
            "an already-safe profile needs no disclosure"
        );
    }

    /// All four built-in profiles are sane postures and must be accepted as-is.
    #[test]
    fn builtin_profiles_pass_through_unchanged() {
        for p in [
            WalletProfile::Treasury,
            WalletProfile::TradingBot,
            WalletProfile::Gaming,
            WalletProfile::Enterprise,
        ] {
            let (effective, note) = enforce_wallet_profile(p, None, false).unwrap();
            assert_eq!(effective, p);
            assert!(note.is_none());
        }
    }

    /// Round 17 (F-16-08): a bar above 1.0 is malformed input, refused before
    /// the pipeline runs — whatever the pin or opt-out says.
    #[test]
    fn min_confidence_above_one_is_refused_up_front() {
        for permissive in [false, true] {
            let r = enforce_wallet_profile(
                WalletProfile::Custom {
                    min_confidence: 1.0000001,
                    min_trust_tier: TrustTier::Unknown,
                },
                None,
                permissive,
            );
            assert!(r.is_err(), "permissive={permissive}: {r:?}");
        }
        let r = enforce_wallet_profile(
            WalletProfile::Custom {
                min_confidence: 2.0,
                min_trust_tier: TrustTier::Unknown,
            },
            Some(WalletProfile::Treasury),
            false,
        );
        assert!(r.is_err(), "a pin does not launder malformed input: {r:?}");
        // Exactly 1.0 is the strictest legal bar and passes through.
        let (effective, note) = enforce_wallet_profile(
            WalletProfile::Custom {
                min_confidence: 1.0,
                min_trust_tier: TrustTier::BattleTested,
            },
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            effective,
            WalletProfile::Custom {
                min_confidence: 1.0,
                min_trust_tier: TrustTier::BattleTested,
            }
        );
        assert!(note.is_none());
    }

    /// Round 17 (F-15-07): a legal confidence bar with an `Unknown` tier
    /// floor is still weaker than Gaming on one axis, and that axis is
    /// clamped and disclosed.
    #[test]
    fn unknown_tier_floor_is_raised_to_the_weakest_builtin() {
        let (effective, note) = enforce_wallet_profile(
            WalletProfile::Custom {
                min_confidence: 0.9,
                min_trust_tier: TrustTier::Unknown,
            },
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            effective,
            WalletProfile::Custom {
                min_confidence: 0.9,
                min_trust_tier: crate::policy_engine::WEAKEST_BUILTIN_MIN_TRUST_TIER,
            }
        );
        assert!(note
            .as_deref()
            .unwrap_or_default()
            .contains("min_trust_tier"));
    }

    /// Pinning wins outright: the operator's configured policy replaces
    /// whatever the caller asked for, including a stricter request (the point
    /// is that the caller does not get to negotiate policy at all).
    #[test]
    fn pinned_profile_overrides_the_request_body() {
        let (effective, note) = enforce_wallet_profile(
            WalletProfile::Custom {
                min_confidence: 0.0,
                min_trust_tier: TrustTier::Unknown,
            },
            Some(WalletProfile::Treasury),
            // Even with the permissive opt-out, a pin still wins.
            true,
        )
        .unwrap();
        assert_eq!(effective, WalletProfile::Treasury);
        assert!(
            note.is_some(),
            "an ignored request profile must be disclosed"
        );
    }

    /// The explicit opt-out exists for genuinely trusted single-tenant use.
    #[test]
    fn permissive_opt_out_allows_a_weak_profile() {
        let weak = WalletProfile::Custom {
            min_confidence: 0.0,
            min_trust_tier: TrustTier::Unknown,
        };
        let (effective, _) = enforce_wallet_profile(weak, None, true).unwrap();
        assert_eq!(effective, weak);
    }

    /// A misconfigured pin must be a startup error, not a silent fallback to
    /// caller-controlled behavior.
    #[test]
    fn pinned_profile_parsing_accepts_valid_and_rejects_invalid() {
        assert_eq!(
            parse_pinned_profile("treasury").unwrap(),
            WalletProfile::Treasury
        );
        assert_eq!(
            parse_pinned_profile("  Gaming ").unwrap(),
            WalletProfile::Gaming
        );
        assert_eq!(
            parse_pinned_profile("custom:0.8:OfficialManifest").unwrap(),
            WalletProfile::Custom {
                min_confidence: 0.8,
                min_trust_tier: TrustTier::OfficialManifest
            }
        );
        for bad in [
            "",
            "nonsense",
            "custom:notanumber:Unknown",
            "custom:0.8:NoSuchTier",
            "custom:1.5:Unknown",
            "custom:0.8",
        ] {
            assert!(
                parse_pinned_profile(bad).is_err(),
                "{bad:?} must be rejected rather than silently ignored"
            );
        }
    }

    // ── P9 lifecycle audit trail ────────────────────────────────────────────

    fn lifecycle_request(body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/audit/event")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    /// The four stages Graphite cannot observe are recorded by the caller that
    /// performed them, and land in the same append-only trail.
    #[tokio::test]
    async fn caller_reported_lifecycle_events_are_recorded() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        use tower::ServiceExt;

        // A signature has to be one (Round 12): 64 bytes, base58.
        let signature = bs58::encode([0x11u8; 64]).into_string();
        for ev in ["signing", "submission", "confirmation", "finalization"] {
            let resp = app
                .clone()
                .oneshot(lifecycle_request(serde_json::json!({
                    "event_type": ev,
                    "content_hash": "48c65c638aceb5de",
                    "transaction_signature": signature,
                    "reported_by": "wallet-bridge",
                })))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::OK,
                "{ev} must be recordable"
            );
        }

        // The events must actually be on disk, not merely accepted.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        for ev in ["signing", "submission", "confirmation", "finalization"] {
            assert!(
                contents.contains(&format!("\"event_type\":\"{ev}\"")),
                "{ev} missing from the audit trail"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn verification_row(hash: &str, approved: bool) -> AuditRecord {
        AuditRecord {
            event_type: LifecycleEvent::Verification,
            timestamp: crate::durable::now_utc_rfc3339(),
            audit_trail_id: format!("gr-{hash}"),
            content_hash: hash.to_string(),
            transaction_sha256: None,
            program_id: "11111111111111111111111111111111".to_string(),
            instruction_name: "transfer".to_string(),
            protocol_name: "System Program".to_string(),
            manifest_version: Some("1.0.0".to_string()),
            approved,
            decision: None,
            executable: None,
            confidence: if approved { 0.9 } else { 0.3 },
            risk_status: "Clear".to_string(),
            policy_verdict: if approved { "Approved" } else { "Rejected" }.to_string(),
            l3_status: "inconclusive".to_string(),
            l8_status: "inconclusive".to_string(),
            wallet_profile: None,
        }
    }

    /// Round 9: every field of `/audit/event` is bounded at the boundary.
    /// Before, a 1 MiB `detail` was a 1 MiB line on the audit volume, and
    /// 64 such requests forced a rotation — which, with a max-archives
    /// setting, prunes an archive of real verifications. The body limit is
    /// 1 MiB, so the request below is the largest one the server accepts.
    #[tokio::test]
    async fn lifecycle_event_fields_are_bounded_at_the_boundary() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        let before = std::fs::metadata(audit_path(&dir))
            .map(|m| m.len())
            .unwrap_or(0);
        let padding = "x".repeat(1_000_000);
        for (field, value) in [
            ("detail", padding.clone()),
            ("reported_by", padding.clone()),
            ("audit_trail_id", padding.clone()),
            ("transaction_signature", "s".repeat(91)),
        ] {
            let (status, body) = post_json(
                &app,
                "/audit/event",
                None,
                serde_json::json!({
                    "event_type": "signing",
                    "content_hash": "48c65c638aceb5de",
                    field: value,
                }),
            )
            .await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "{field}: {body}"
            );
            let err = body["error"].as_str().unwrap();
            assert!(err.contains(field) && err.contains("characters"), "{err}");
            assert!(
                !err.contains("xxxx"),
                "the rejection must not echo the value"
            );
        }
        // Malformed join keys: not the shape of a content_hash.
        for bad in [
            "abc123",
            "AFB61D8865B4CB68",
            "48c65c638aceb5deff",
            "zzzzzzzzzzzzzzzz",
        ] {
            let (status, body) = post_json(
                &app,
                "/audit/event",
                None,
                serde_json::json!({ "event_type": "signing", "content_hash": bad }),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{bad}: {body}");
        }
        // A refused event records no lifecycle row. Since the 2026-10-20
        // audit each refusal leaves a bounded error row, as `/verify`'s do —
        // and none of them carries the value: the trail cannot be filled
        // through this route.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap_or_default();
        let new_rows: Vec<&str> = contents[before as usize..].lines().collect();
        assert_eq!(new_rows.len(), 8, "one error row per refusal");
        for row in new_rows {
            assert!(row.len() < 1024, "an error row of {} bytes", row.len());
            assert!(!row.contains("xxxx"), "the row echoes the value: {row}");
            assert!(row.contains("POST /audit/event"), "{row}");
            assert!(!row.contains("\"event_type\":\"signing\""), "{row}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 9: the one fact Graphite can establish about a caller-reported
    /// event is what its own trail says about the hash. Recorded on the row,
    /// returned to the caller, counted — and a report against a BLOCKED
    /// verdict is the gate being bypassed, counted separately.
    #[tokio::test]
    async fn lifecycle_events_carry_the_verdict_on_record() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        assert!(log.append(&verification_row("bbbbbbbbbbbbbbbb", false)));
        // Verified twice: the newest decision governs.
        assert!(log.append(&verification_row("cccccccccccccccc", true)));
        assert!(log.append(&verification_row("cccccccccccccccc", false)));
        let metrics = state.metrics.clone();
        let app = build_app(state, vec![]);
        for (hash, expect) in [
            ("aaaaaaaaaaaaaaaa", "approved"),
            ("bbbbbbbbbbbbbbbb", "blocked"),
            ("cccccccccccccccc", "blocked"),
            ("dddddddddddddddd", "not_found"),
        ] {
            let (status, body) = post_json(
                &app,
                "/audit/event",
                None,
                serde_json::json!({
                    "event_type": "signing",
                    "content_hash": hash,
                    "reported_by": "bridge",
                }),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["verdict_on_record"], expect, "{hash}: {body}");
        }
        assert_eq!(
            metrics
                .lifecycle_on_blocked
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .lifecycle_unverified
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        assert_eq!(
            contents
                .matches("\"verdict_on_record\":\"blocked\"")
                .count(),
            2
        );
        assert_eq!(
            contents
                .matches("\"verdict_on_record\":\"not_found\"")
                .count(),
            1
        );
        assert_eq!(
            contents
                .matches("\"verdict_on_record\":\"approved\"")
                .count(),
            1
        );
        // The verification rows are untouched by the events: still four, still
        // the same decisions, and a lifecycle row never reads as a verdict.
        let (records, _, total, _) = log.read_tail_filtered(100, AuditSelector::All);
        assert_eq!(total, 4);
        assert_eq!(records.iter().filter(|r| r.approved).count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 10: `verdict_on_record` resolves by the most exact key supplied,
    /// never by a coarser one, and keys that contradict each other are a
    /// refused attestation. A (approved) and B (blocked) share a
    /// `content_hash`; A is the newer record.
    #[tokio::test]
    async fn lifecycle_verdict_resolves_by_the_most_exact_key_and_refuses_contradiction() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        let h = "aaaaaaaaaaaaaaaa";
        let tx_a = "a".repeat(64);
        let tx_b = "b".repeat(64);
        let mut b = verification_row(h, false);
        b.audit_trail_id = "gr-b".to_string();
        b.transaction_sha256 = Some(tx_b.clone());
        assert!(log.append(&b));
        let mut a = verification_row(h, true);
        a.audit_trail_id = "gr-a".to_string();
        a.transaction_sha256 = Some(tx_a.clone());
        assert!(log.append(&a));
        let app = build_app(state, vec![]);
        let post = |body: serde_json::Value| {
            let app = app.clone();
            async move { post_json(&app, "/audit/event", None, body).await }
        };

        // content_hash alone: the newest carrier of that instruction — A.
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": h})).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["verdict_on_record"], "approved");
        assert_eq!(body["verdict_on_record_key"], "content_hash");

        // transaction_sha256 of B: B's block, whatever content_hash says.
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": h, "transaction_sha256": tx_b})).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["verdict_on_record"], "blocked");
        assert_eq!(body["verdict_on_record_key"], "transaction_sha256");

        // audit_trail_id of B: the same, by the most exact key.
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": h, "audit_trail_id": "gr-b"})).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["verdict_on_record"], "blocked");
        assert_eq!(body["verdict_on_record_key"], "audit_trail_id");

        // Contradictions are refused, not resolved in the caller's favour.
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": h, "audit_trail_id": "gr-a", "transaction_sha256": tx_b})).await;
        assert_eq!(s, axum::http::StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error_type"], "InconsistentKeys");
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": "ffffffffffffffff", "audit_trail_id": "gr-a"})).await;
        assert_eq!(s, axum::http::StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error_type"], "InconsistentKeys");

        // A spoofed id is not rescued by the real content_hash beside it.
        let (s, body) = post(serde_json::json!({"event_type": "signing", "content_hash": h, "audit_trail_id": "gr-nope"})).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["verdict_on_record"], "not_found");
        assert_eq!(body["verdict_on_record_key"], "audit_trail_id");

        // Malformed digests are refused on both endpoints.
        let (s, _) = post(serde_json::json!({"event_type": "signing", "content_hash": h, "transaction_sha256": "abc"})).await;
        assert_eq!(s, axum::http::StatusCode::BAD_REQUEST);
        let (s, _) = post_json(
            &app,
            "/verify/execution",
            None,
            serde_json::json!({"signature": "5xSig", "transaction_sha256": "ABC"}),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::BAD_REQUEST);

        // The rows say which key resolved them.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        assert!(
            contents.contains("\"verdict_on_record_key\":\"transaction_sha256\""),
            "{contents}"
        );
        assert!(
            contents.contains("\"verdict_on_record_key\":\"audit_trail_id\""),
            "{contents}"
        );
        assert_eq!(
            contents
                .matches("\"verdict_on_record\":\"blocked\"")
                .count(),
            2
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A caller must NOT be able to inject a self-observed event. Accepting a
    /// caller-supplied "verification" row would let anyone forge an approval
    /// into the audit trail — the exact record a dispute would be settled on.
    #[tokio::test]
    async fn a_caller_cannot_forge_a_self_observed_event() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        use tower::ServiceExt;

        // `operator_action` too (R-P14, Round 28): the list is written out
        // here rather than read from `LifecycleEvent::emission`, so a change
        // to that table that makes a self-observed event reportable fails
        // here instead of passing with it.
        for ev in [
            "verification",
            "construction",
            "simulation",
            "operator_action",
        ] {
            let resp = app
                .clone()
                .oneshot(lifecycle_request(serde_json::json!({
                    "event_type": ev,
                    "content_hash": "48c65c638aceb5de",
                })))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::BAD_REQUEST,
                "a caller must not be able to write a {ev} record"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-P14 (Round 28): every lifecycle event reaches the audit trail
    /// where `LifecycleEvent::emission` says it does.
    ///
    /// - `LifecycleEvent::ALL` is the enum serde derives: the
    ///   unknown-variant error lists every variant, so one missing from the
    ///   list fails here.
    /// - A caller-reported event is accepted at `/audit/event` and is on
    ///   disk; every other event is refused there, so the trail holds only
    ///   what Graphite observed under those names.
    /// - A Graphite row is written by its route: `/verify` and
    ///   `/admin/quarantine` are driven, and the row read back.
    /// - A stage recorded on the verification row has its field there,
    ///   filled.
    /// - Every route named is one the server serves.
    #[tokio::test]
    async fn every_lifecycle_event_reaches_the_trail() {
        use crate::durable::Emission;
        let names: Vec<String> = LifecycleEvent::ALL
            .iter()
            .map(|e| {
                serde_json::to_value(e)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let err = serde_json::from_str::<LifecycleEvent>("\"not_a_lifecycle_event\"")
            .unwrap_err()
            .to_string();
        // "unknown variant `x`, expected one of `a`, `b`, ... at line 1"
        let mut derived: Vec<String> = err
            .split("expected one of ")
            .nth(1)
            .expect("serde lists the variants")
            .split('`')
            .skip(1)
            .step_by(2)
            .map(String::from)
            .collect();
        let mut listed = names.clone();
        listed.sort();
        derived.sort();
        assert_eq!(
            listed, derived,
            "LifecycleEvent::ALL must list every variant"
        );

        let (state, dir, operator_key) = keyed_state();
        let app = build_app(state, vec![]);
        let signature = bs58::encode([0x22u8; 64]).into_string();
        let rows = |dir: &std::path::Path| -> Vec<serde_json::Value> {
            std::fs::read_to_string(audit_path(dir))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        };
        let routes = [
            "/verify",
            "/audit/event",
            "/verify/execution",
            "/admin/quarantine",
        ];
        let mut verification_row: Option<serde_json::Value> = None;
        for (event, name) in LifecycleEvent::ALL.into_iter().zip(&names) {
            // The caller-reporting endpoint refuses every event Graphite
            // observes itself, and takes every one it does not.
            let (status, body) = post_json(
                &app,
                "/audit/event",
                Some(VERIFY_TEST_KEY),
                serde_json::json!({
                    "event_type": name,
                    "content_hash": "48c65c638aceb5de",
                    "transaction_signature": signature,
                    "reported_by": "r-p14",
                }),
            )
            .await;
            match event.emission() {
                Emission::CallerReported { also_observed } => {
                    assert_eq!(status, axum::http::StatusCode::OK, "{name}: {body}");
                    assert!(
                        rows(&dir).iter().any(|r| r["event_type"] == *name.as_str()),
                        "{name} is not on the trail"
                    );
                    if let Some(route) = also_observed {
                        assert!(routes.contains(&route), "{name}: {route} is not a route");
                    }
                }
                Emission::GraphiteRow { route } => {
                    assert_eq!(
                        status,
                        axum::http::StatusCode::BAD_REQUEST,
                        "a caller must not write a {name} row: {body}"
                    );
                    assert!(routes.contains(&route), "{name}: {route} is not a route");
                    let (status, body) = match route {
                        "/verify" => {
                            post_json(
                                &app,
                                "/verify",
                                Some(VERIFY_TEST_KEY),
                                serde_json::json!({
                                    "proposed_intent": {
                                        "intent_type": "transfer",
                                        "raw_natural_language": "Transfer 1 SOL to friend",
                                        "confidence_of_parse": 0.95
                                    },
                                    "program_id": SYSTEM,
                                    "protocol_version": "1.0.0",
                                    "instruction_discriminator": "02000000",
                                    "account_addresses": [
                                        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                                        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
                                    ],
                                    "wallet_profile": "TradingBot"
                                }),
                            )
                            .await
                        }
                        "/admin/quarantine" => {
                            post_json(
                                &app,
                                "/admin/quarantine",
                                Some(&operator_key),
                                serde_json::json!({"program_id": SYSTEM, "reason": "r-p14"}),
                            )
                            .await
                        }
                        "/verify/execution" => {
                            // No RPC is attached, so the chain cannot answer:
                            // the row is a check, never a confirmation.
                            post_json(
                                &app,
                                "/verify/execution",
                                Some(VERIFY_TEST_KEY),
                                serde_json::json!({"signature": signature}),
                            )
                            .await
                        }
                        other => panic!("{name}: no driver for {other}; add one here"),
                    };
                    assert_eq!(status, axum::http::StatusCode::OK, "{route}: {body}");
                    let row = rows(&dir)
                        .into_iter()
                        .rev()
                        .find(|r| r["event_type"] == *name.as_str())
                        .unwrap_or_else(|| panic!("{route} wrote no {name} row"));
                    if event == LifecycleEvent::Verification {
                        verification_row = Some(row);
                    }
                }
                Emission::OnTheVerificationRow { .. } => {
                    assert_eq!(
                        status,
                        axum::http::StatusCode::BAD_REQUEST,
                        "a caller must not write a {name} row: {body}"
                    );
                }
            }
        }
        let row = verification_row.expect("the verification row was written");
        for event in LifecycleEvent::ALL {
            if let Emission::OnTheVerificationRow { field } = event.emission() {
                let value = row[field].as_str().unwrap_or_default();
                assert!(
                    !value.trim().is_empty(),
                    "{event:?} is recorded as `{field}` on the verification row, which is empty: {row}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The join key is mandatory — an event that cannot be tied back to a
    /// verification is unreconcilable and therefore worthless as audit.
    #[tokio::test]
    async fn a_lifecycle_event_without_a_content_hash_is_rejected() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        use tower::ServiceExt;
        let resp = app
            .oneshot(lifecycle_request(serde_json::json!({
                "event_type": "signing",
                "content_hash": "   ",
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The endpoint is authenticated like every other non-health route —
    /// anyone able to write to the audit trail could otherwise pollute it.
    #[tokio::test]
    async fn the_lifecycle_endpoint_requires_auth() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use tower::ServiceExt;
        let resp = app
            .oneshot(lifecycle_request(serde_json::json!({
                "event_type": "signing",
                "content_hash": "48c65c638aceb5de",
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/metrics` exposes operational counters — but it also reveals traffic
    /// volume, block rates, and auth-failure counts, so it must sit BEHIND the
    /// API key like every other non-health endpoint. Only `/health` is open,
    /// for load balancers.
    #[tokio::test]
    async fn metrics_endpoint_requires_auth_and_health_does_not() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let mut unauth = axum::http::Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        unauth.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            app.clone().oneshot(unauth).await.unwrap().status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "/metrics must not be publicly readable"
        );

        let mut health = axum::http::Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        health.extensions_mut().insert(ConnectInfo(addr));
        assert_eq!(
            app.clone().oneshot(health).await.unwrap().status(),
            axum::http::StatusCode::OK,
            "/health stays open for load balancers"
        );
        let _ = dir;
    }

    /// The metrics surface must be real: counters that are exported but never
    /// incremented are worse than absent, because operators build alerts on
    /// them. Drive a rejected request and assert the counter actually moves.
    #[tokio::test]
    async fn metrics_counters_reflect_real_events() {
        let (state, dir) = test_state();
        let state = AppState {
            api_key: Some(std::sync::Arc::new("sekret".to_string())),
            ..state
        };
        let app = build_app(state, vec![]);
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Two unauthenticated calls -> two auth failures.
        for _ in 0..2 {
            let mut req = axum::http::Request::builder()
                .uri("/manifests")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        let mut req = axum::http::Request::builder()
            .uri("/metrics")
            .header(header::AUTHORIZATION, "Bearer sekret")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);

        assert!(
            text.contains("graphite_auth_failures_total 2"),
            "auth failures must be counted, got:\n{text}"
        );
        // Prometheus text format requires HELP/TYPE metadata to be parseable.
        assert!(text.contains("# TYPE graphite_auth_failures_total counter"));
        assert!(text.contains("graphite_audit_enabled 1"));
        let _ = dir;
    }

    /// Real-listener concurrency storm: 8 parallel workers × 25 /verify calls
    /// plus concurrent dashboard reads against one bound server. Proves the
    /// shared state (Arc<Mutex<SemanticGraphStore>>, Mutex-guarded audit log,
    /// per-IP rate limiter) survives real parallelism with zero 5xx/panics,
    /// and that the audit log durably records every concurrent verification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_verify_storm_shares_state_and_stays_healthy() {
        let (mut state, dir) = test_state();
        // Raise the per-IP limit so the storm exercises concurrency, not 429s.
        state.rate = RateLimiter::with_capacity(10_000, 100_000.0);
        let assert_core = state.core.clone();
        let app = build_app(state, vec![]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );
        let server_task = tokio::spawn(async move {
            serve.await.expect("server must run");
        });

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");
        let body = serde_json::json!({
            "proposed_intent": {
                "intent_type": "transfer",
                "raw_natural_language": "Transfer 1 SOL to friend",
                "confidence_of_parse": 0.95
            },
            "program_id": "11111111111111111111111111111111",
            "protocol_version": "1.0.0",
            "instruction_discriminator": "02000000",
            "account_addresses": [
                "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
            ],
            "wallet_profile": "TradingBot"
        })
        .to_string();

        const WORKERS: usize = 8;
        const PER_WORKER: usize = 25;
        let start = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..WORKERS {
            let client = client.clone();
            let body = body.clone();
            let base = base.clone();
            tasks.push(tokio::spawn(async move {
                let mut results = Vec::with_capacity(PER_WORKER);
                for _ in 0..PER_WORKER {
                    let resp = client
                        .post(format!("{base}/verify"))
                        .header("content-type", "application/json")
                        .body(body.clone())
                        .send()
                        .await
                        .expect("post must succeed");
                    let status = resp.status();
                    let json: serde_json::Value =
                        resp.json().await.unwrap_or(serde_json::Value::Null);
                    results.push((status, json.get("confidence").and_then(|c| c.as_f64())));
                }
                results
            }));
        }
        // Concurrent dashboard reads on the same server.
        let mut readers = Vec::new();
        for _ in 0..4 {
            let client = client.clone();
            let base = base.clone();
            readers.push(tokio::spawn(async move {
                let mut out = Vec::new();
                for path in [
                    "/manifests",
                    "/api/graph",
                    "/api/confidence-history",
                    "/health",
                ] {
                    let r = client
                        .get(format!("{base}{path}"))
                        .send()
                        .await
                        .expect("get must succeed");
                    out.push((path.to_string(), r.status()));
                }
                out
            }));
        }
        let mut all: Vec<(reqwest::StatusCode, Option<f64>)> = Vec::new();
        for t in tasks {
            all.extend(t.await.expect("worker task must not panic"));
        }
        for r in readers {
            for (path, status) in r.await.expect("reader task must not panic") {
                assert_eq!(status, reqwest::StatusCode::OK, "GET {path} under load");
            }
        }
        let elapsed = start.elapsed();

        for (status, confidence) in &all {
            assert_eq!(*status, reqwest::StatusCode::OK, "verify under concurrency");
            let c = confidence.expect("confidence must be a number");
            assert!(
                c.is_finite() && (0.0..=1.0).contains(&c),
                "confidence out of range: {c}"
            );
        }
        assert_eq!(all.len(), WORKERS * PER_WORKER, "every verify answered");

        // The shared semantic graph survived uncorrupted: the seeded System
        // evidence is still intact (verify_async is a read-only scorer — see
        // forensic report C10).
        let snapshot = assert_core.graph_snapshot();
        let sys = snapshot
            .nodes
            .iter()
            .find(|n| n.program_id == "11111111111111111111111111111111")
            .expect("seeded system node must survive the storm");
        assert_eq!(sys.battle_tested_tx_count, 1500);

        // Durability: the audit log durably recorded ALL 200 verifications
        // despite 8 concurrent writers (Mutex-guarded append). Valid only
        // because the server task is fully joined above (abort → router drop
        // → audit File handle drop → flush), so every append is visible to a
        // fresh open.
        // Read only (Round 30): the server still holds the writer lock.
        let log = AuditLog::open_read_only(audit_path(&dir)).unwrap();
        let (records, errors, total, _) = log.read_tail_filtered(10_000, AuditSelector::All);
        // The eight concurrent writers left one unbroken hash chain.
        let chain = log.verify(&[], None).unwrap();
        assert!(chain.intact(), "{chain:?}");
        assert_eq!(chain.chained_records as usize, WORKERS * PER_WORKER);
        assert_eq!(
            total,
            WORKERS * PER_WORKER,
            "every concurrent verification must reach the audit log"
        );
        assert_eq!(records.len(), WORKERS * PER_WORKER);
        assert!(errors.is_empty(), "no error records from a clean storm");

        server_task.abort();
        let _ = server_task.await;
        let rate = (WORKERS * PER_WORKER) as f64 / elapsed.as_secs_f64();
        println!(
            "stress: {WORKERS}×{PER_WORKER} verifies + 16 dashboard reads in {}ms → {rate:.0} verifies/s (includes dashboard reads)",
            elapsed.as_millis()
        );
    }

    /// Hostile-body battery against /verify: invalid JSON, wrong types, deep
    /// nesting, a >1MB body (body-limit middleware), a 200k-account list
    /// (body cap), a 2k-account list (semantic MAX_ACCOUNTS cap), and random
    /// bytes. Every case must be a clean 4xx — never a 5xx, never a panic —
    /// and the server must still answer /health afterwards.
    #[tokio::test]
    async fn hostile_verify_bodies_never_return_5xx() {
        use axum::body::Body;
        use tower::ServiceExt;

        let (mut state, _dir) = test_state();
        state.rate = RateLimiter::with_capacity(10_000, 100_000.0);
        let app = build_app(state, vec![]);

        let two_k_accounts: String = (0..2_000)
            .map(|_| "\"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"")
            .collect::<Vec<_>>()
            .join(",");
        let two_hundred_k_accounts: String = (0..200_000)
            .map(|_| "\"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\"")
            .collect::<Vec<_>>()
            .join(",");
        let deep = format!("{{\"a\":{}}}", "[".repeat(5000) + &"]".repeat(5000));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("invalid json", b"{ not json".to_vec()),
            ("empty body", Vec::new()),
            ("null", b"null".to_vec()),
            ("json array", b"[1,2,3]".to_vec()),
            ("wrong types", br#"{"program_id": 123, "account_addresses": "x"}"#.to_vec()),
            ("partial input", br#"{"program_id":"11111111111111111111111111111111"}"#.to_vec()),
            ("deeply nested", deep.into_bytes()),
            ("5MB string", format!("{{\"program_id\":\"{}\"}}", "1".repeat(5_000_000)).into_bytes()),
            (
                "200k accounts (over body cap)",
                format!(
                    "{{\"program_id\":\"11111111111111111111111111111111\",\"instruction_discriminator\":\"02000000\",\"account_addresses\":[{two_hundred_k_accounts}]}}"
                )
                .into_bytes(),
            ),
            (
                "2k accounts (over MAX_ACCOUNTS=64)",
                format!(
                    "{{\"program_id\":\"11111111111111111111111111111111\",\"instruction_discriminator\":\"02000000\",\"account_addresses\":[{two_k_accounts}]}}"
                )
                .into_bytes(),
            ),
            ("random bytes", vec![0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f]),
        ];

        for (name, bytes) in cases {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(bytes))
                .unwrap();
            let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            let resp = app
                .clone()
                .oneshot(req)
                .await
                .expect("router must never panic on hostile input");
            let status = resp.status();
            assert!(
                status.is_client_error(),
                "{name}: expected 4xx, got {status} — a 5xx here is a bug"
            );
        }

        // Server still healthy after the barrage.
        let (status, _) = get_json(&app, "/health").await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn panicking_handler_returns_500_and_server_survives() {
        // Certification item: a handler that panics must produce a clean 500
        // (no connection drop, no internal details leaked) and the server must
        // continue serving subsequent requests.
        use tower::ServiceExt;

        // A dedicated panicking route wrapped in the SAME catch-panic layer
        // the production router uses.
        async fn boom() -> Response {
            panic!("deliberate test panic — must be caught");
        }
        let app = Router::new()
            .route("/boom", get(boom))
            .route("/alive", get(|| async { "ok" }))
            .layer(CatchPanicLayer::custom(
                |_panic: Box<dyn std::any::Any + Send + 'static>| {
                    axum::http::Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(axum::body::Bytes::from_static(
                            b"{\"error\":\"internal server error\"}",
                        )))
                        .unwrap()
                },
            ));

        let mut req = axum::http::Request::builder()
            .uri("/boom")
            .body(axum::body::Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "panic must map to 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("internal server error") && !body.contains("deliberate test panic"),
            "panic body must be generic, got: {body}"
        );

        // The router is still alive after the panic.
        let mut alive = axum::http::Request::builder()
            .uri("/alive")
            .body(axum::body::Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        alive.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(alive).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "server must continue serving after a handler panic"
        );
    }

    /// Round 12: a second process on the same data directory is refused
    /// while the first holds it, and admitted once it lets go.
    #[test]
    fn a_data_directory_is_held_by_one_process() {
        let dir = std::env::temp_dir().join(format!(
            "graphite-lock-{}-{}",
            std::process::id(),
            crate::durable::now_utc_rfc3339().replace([':', '.'], "-")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = lock_data_dir(&dir).expect("the first holder");
        let err = lock_data_dir(&dir).expect_err("a second holder is refused");
        assert!(
            err.to_string().contains("another Graphite process"),
            "{err}"
        );
        drop(first);
        let _again = lock_data_dir(&dir).expect("free once released");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Audit 2026-10-20 (M4): an L8 check that did not see the transaction
    /// included writes an `execution_check` row, never a Graphite-attested
    /// `confirmation`, so the caller's truthful `submission` that follows is
    /// not reported as arriving after a confirmation.
    #[tokio::test]
    async fn an_l8_check_that_saw_nothing_is_not_a_confirmation() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        let signature = sig(5);
        let (s, body) = post_json(
            &app,
            "/verify/execution",
            None,
            serde_json::json!({ "signature": signature, "content_hash": "48c65c638aceb5de" }),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(row["event_type"], "execution_check", "{row}");
        assert_eq!(row["observed_by_graphite"], true);
        let (s, body) = post_json(
            &app,
            "/audit/event",
            None,
            serde_json::json!({
                "event_type": "submission",
                "content_hash": "48c65c638aceb5de",
                "transaction_signature": signature,
            }),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let anomalies = body["sequence_anomalies"].as_array().unwrap();
        assert!(
            !anomalies
                .iter()
                .any(|a| a.as_str().unwrap_or_default().contains("out of order")),
            "a check that saw nothing ordered the caller's report: {body}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round 12: an L8 row attributed by `content_hash` names *a*
    /// transaction carrying the instruction, so the resolved record's exact
    /// keys must not be written onto this signature's row — the trail would
    /// then hold "this signature is that transaction", a link the sequence
    /// check later reports as a conflict against a truthful report.
    #[tokio::test]
    async fn an_l8_row_attributed_by_content_hash_carries_no_exact_keys() {
        use std::io::{Read, Write};
        // A cluster that confirms every signature and holds no bytes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 65536];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("getSignatureStatuses") {
                    r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":2},"value":[{"slot":12345,"confirmations":10,"confirmationStatus":"finalized","err":null,"status":{"Ok":null}}]}}"#
                } else {
                    r#"{"jsonrpc":"2.0","id":1,"result":null}"#
                };
                let head = format!(
                    "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

{body}",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
            }
        });
        let (mut state, dir) = test_state();
        Arc::get_mut(&mut state.core)
            .expect("fresh state has one owner")
            .attach_rpc_client(crate::rpc_client::SolanaRpcClient::new(
                crate::rpc_client::RpcConfig {
                    endpoint: format!("http://{addr}"),
                    timeout: std::time::Duration::from_secs(5),
                    max_retries: 0,
                    ..Default::default()
                },
            ));
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        let app = build_app(state, vec![]);
        let signature = bs58::encode([0x21u8; 64]).into_string();
        let (s, body) = post_json(
            &app,
            "/verify/execution",
            None,
            serde_json::json!({ "signature": signature, "content_hash": "aaaaaaaaaaaaaaaa" }),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["attribution"], "content_hash", "{body}");
        assert_eq!(body["recorded_audit_trail_id"], "gr-aaaaaaaaaaaaaaaa");
        assert!(
            body["chain_bytes_unavailable"]
                .as_str()
                .unwrap()
                .contains("null"),
            "{body}"
        );
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(row["event_type"], "confirmation");
        assert_eq!(row["observed_by_graphite"], true);
        assert_eq!(row["transaction_signature"], signature);
        assert!(
            row.get("audit_trail_id").is_none_or(|v| v.is_null()),
            "{row}"
        );
        assert!(
            row.get("transaction_sha256").is_none_or(|v| v.is_null()),
            "{row}"
        );
        assert!(
            row["detail"]
                .as_str()
                .unwrap()
                .contains("attribution: ContentHash"),
            "{row}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Round 12: the lifecycle sequence ────────────────────────────────────
    //
    // Every caller-reported event is an attestation, recorded as reported.
    // What Graphite can add is how the report sits against the rows already
    // on record for the same transaction: a duplicate (a retry), a stage out
    // of order, a stage with no predecessor, or — the one that means a
    // report is false — a signature that differs from the one already
    // attached. Named on the row, returned, counted; never refused.

    fn sig(byte: u8) -> String {
        bs58::encode([byte; 64]).into_string()
    }

    /// The happy path carries no anomaly at any stage, and a retry of the
    /// submission (the bridge did not hear the first answer) is named as the
    /// duplicate it is rather than counted as a second submission.
    #[tokio::test]
    async fn lifecycle_reports_in_order_carry_no_anomaly_and_a_retry_is_a_duplicate() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        let metrics = state.metrics.clone();
        let app = build_app(state, vec![]);
        let id = "gr-aaaaaaaaaaaaaaaa";
        let post = |ev: &'static str, signature: Option<String>| {
            let app = app.clone();
            async move {
                post_json(
                    &app,
                    "/audit/event",
                    None,
                    serde_json::json!({
                        "event_type": ev,
                        "content_hash": "aaaaaaaaaaaaaaaa",
                        "audit_trail_id": id,
                        "transaction_signature": signature,
                        "reported_by": "bridge",
                    }),
                )
                .await
            }
        };
        let (s, body) = post("signing", None).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["sequence_anomalies"], serde_json::json!([]));
        assert_eq!(body["prior_events_on_record"], 0);
        let (s, body) = post("submission", Some(sig(7))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["sequence_anomalies"], serde_json::json!([]), "{body}");
        assert_eq!(body["prior_events_on_record"], 1);
        // The retry.
        let (s, body) = post("submission", Some(sig(7))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let anomalies = body["sequence_anomalies"].as_array().unwrap();
        assert_eq!(anomalies.len(), 1, "{body}");
        assert!(
            anomalies[0]
                .as_str()
                .unwrap()
                .starts_with("duplicate: Submission"),
            "{body}"
        );
        let (s, body) = post("confirmation", Some(sig(7))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["sequence_anomalies"], serde_json::json!([]), "{body}");
        let (s, body) = post("finalization", Some(sig(7))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["sequence_anomalies"], serde_json::json!([]), "{body}");
        assert_eq!(
            metrics
                .lifecycle_sequence_anomalies
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // The rows carry what the responses said.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        assert_eq!(
            contents.matches("\"sequence_anomalies\"").count(),
            1,
            "{contents}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Out of order, unpreceded, and the signature conflict.
    #[tokio::test]
    async fn lifecycle_reports_out_of_sequence_are_named_and_a_second_signature_is_loud() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        let metrics = state.metrics.clone();
        let app = build_app(state, vec![]);
        let id = "gr-aaaaaaaaaaaaaaaa";
        let post = |ev: &'static str, signature: Option<String>| {
            let app = app.clone();
            async move {
                post_json(
                    &app,
                    "/audit/event",
                    None,
                    serde_json::json!({
                        "event_type": ev,
                        "content_hash": "aaaaaaaaaaaaaaaa",
                        "audit_trail_id": id,
                        "transaction_signature": signature,
                    }),
                )
                .await
            }
        };
        // A confirmation first: unpreceded (no submission on record).
        let (s, body) = post("confirmation", Some(sig(1))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let a = body["sequence_anomalies"].as_array().unwrap().clone();
        assert_eq!(a.len(), 1, "{body}");
        assert!(
            a[0].as_str()
                .unwrap()
                .starts_with("unpreceded: Confirmation"),
            "{body}"
        );
        // Then a signing: out of order (a confirmation is already on record).
        let (s, body) = post("signing", None).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let a = body["sequence_anomalies"].as_array().unwrap().clone();
        assert_eq!(a.len(), 1, "{body}");
        assert!(
            a[0].as_str().unwrap().starts_with("out of order: Signing"),
            "{body}"
        );
        // Then a submission under a DIFFERENT signature: the conflict, plus
        // out of order.
        let (s, body) = post("submission", Some(sig(2))).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let a: Vec<String> = body["sequence_anomalies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            a.iter().any(|x| x.starts_with("signature conflict")),
            "{a:?}"
        );
        assert!(
            a.iter().any(|x| x.starts_with("out of order: Submission")),
            "{a:?}"
        );
        let conflict = a
            .iter()
            .find(|x| x.starts_with("signature conflict"))
            .unwrap();
        assert!(conflict.contains(&sig(1)), "{conflict}");
        // Still recorded: the trail keeps what was reported, with the finding.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        assert!(contents.contains("signature conflict"), "{contents}");
        assert_eq!(
            metrics
                .lifecycle_sequence_anomalies
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A4-11, and its review F9 (2026-09-29 audit): reports for one
    /// transaction are taken one at a time, from the history read to the
    /// append. Sixteen submissions under sixteen different signatures, sent
    /// together: the first one recorded is the only one without a
    /// `signature conflict`. Without the critical section several read a
    /// history holding none of the others, and two signatures for one
    /// transaction were recorded with no conflict on either. The reports use
    /// `RACE_WINDOW_TRAIL_ID`, which the handler holds open between the read
    /// and the append in tests, so the race is certain rather than lucky: the
    /// first version of this test passed with the lock removed (break B54).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reports_of_two_signatures_cannot_both_miss_the_conflict() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("cafecafecafecafe", true)));
        let app = build_app(state, vec![]);
        const REPORTS: u8 = 16;
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(REPORTS as usize));
        let reports: Vec<_> = (1..=REPORTS)
            .map(|i| {
                let app = app.clone();
                let start = start.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    post_json(
                        &app,
                        "/audit/event",
                        None,
                        serde_json::json!({
                            "event_type": "submission",
                            "content_hash": "cafecafecafecafe",
                            // Held open between read and append in tests.
                            "audit_trail_id": RACE_WINDOW_TRAIL_ID,
                            "transaction_signature": sig(i),
                        }),
                    )
                    .await
                })
            })
            .collect();
        let mut without_conflict = 0;
        for report in reports {
            let (status, body) = report.await.unwrap();
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            let conflict = body["sequence_anomalies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str().unwrap().starts_with("signature conflict"));
            without_conflict += usize::from(!conflict);
        }
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            without_conflict, 1,
            "{without_conflict} of {REPORTS} different signatures for one transaction were \
             recorded with no `signature conflict`: concurrent reports each read a history \
             without the others"
        );
    }

    /// A4-09 (2026-09-29 audit): a verdict is counted on /metrics only once it
    /// is on the audit trail. Before the fix the approved/blocked counter went
    /// up before the append, so a verdict refused with 503 because the trail
    /// could not be written still showed as one Graphite had given.
    #[tokio::test]
    async fn a_verdict_that_could_not_be_recorded_is_not_counted() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        // Make every append fail, as `lifecycle_event_reports_an_unrecorded_
        // event_instead_of_panicking` does: a read-only handle in the log.
        {
            let ro = std::fs::OpenOptions::new()
                .read(true)
                .open(audit_path(&dir))
                .unwrap();
            *log.file.lock().unwrap() = ro;
        }
        let metrics = state.metrics.clone();
        let app = build_app(state, vec![]);
        let input: serde_json::Value =
            serde_json::from_str(include_str!("../../examples/verify-input.json"))
                .expect("the committed example parses");
        let (status, body) = post_json(&app, "/verify", None, input).await;
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "precondition: the verdict cannot be recorded, so it is refused: {body}"
        );
        assert_eq!(body["error_type"], "AuditWriteFailed", "{body}");
        let counted = metrics
            .verify_approved
            .load(std::sync::atomic::Ordering::Relaxed)
            + metrics
                .verify_blocked
                .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            counted, 0,
            "a verdict refused with 503 because it could not be written was counted on /metrics \
             as one Graphite gave"
        );
    }

    /// F9 (review of the 2026-09-29 audit's fix A4-04): dashboard scans run on
    /// the blocking pool, which every audit append shares, so at most
    /// `MAX_CONCURRENT_DASHBOARD_SCANS` run at once and further polls wait for
    /// a permit instead of taking the pool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dashboard_scans_run_a_bounded_number_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);
        let scans: Vec<_> = (0..3 * MAX_CONCURRENT_DASHBOARD_SCANS)
            .map(|_| {
                tokio::spawn(dashboard_scan(|| {
                    let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
                    PEAK.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    RUNNING.fetch_sub(1, Ordering::SeqCst);
                }))
            })
            .collect();
        for scan in scans {
            scan.await.unwrap();
        }
        let peak = PEAK.load(Ordering::SeqCst);
        assert!(peak > 1, "precondition: the scans ran concurrently");
        assert!(
            peak <= MAX_CONCURRENT_DASHBOARD_SCANS,
            "{peak} dashboard scans held the blocking pool at once (cap \
             {MAX_CONCURRENT_DASHBOARD_SCANS})"
        );
    }

    /// W21 (external review, verified 2026-10-03): a request that times out
    /// abandons its scan, and the scan used to give back its slot as it did,
    /// so abandoned scans ran uncounted. The slot is held until the scan ends.
    #[tokio::test]
    async fn an_abandoned_scan_keeps_its_slot_until_it_ends() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);
        let abandoned: Vec<_> = (0..3 * MAX_CONCURRENT_DASHBOARD_SCANS)
            .map(|_| {
                tokio::spawn(tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    dashboard_scan(|| {
                        let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
                        PEAK.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        RUNNING.fetch_sub(1, Ordering::SeqCst);
                    }),
                ))
            })
            .collect();
        for task in abandoned {
            assert!(
                task.await.unwrap().is_err(),
                "precondition: every request timed out"
            );
        }
        // The scans run on after their requests are gone; let them start,
        // then wait them out.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        while RUNNING.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let peak = PEAK.load(Ordering::SeqCst);
        assert!(
            peak <= MAX_CONCURRENT_DASHBOARD_SCANS,
            "{peak} abandoned scans ran at once (cap {MAX_CONCURRENT_DASHBOARD_SCANS})"
        );
    }

    /// From submission onward the signature is required, and a signature
    /// has to be one. Signing needs none: it precedes the signature.
    #[tokio::test]
    async fn submission_onward_requires_a_real_signature() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        for ev in ["submission", "confirmation", "finalization"] {
            let (s, body) = post_json(
                &app,
                "/audit/event",
                None,
                serde_json::json!({ "event_type": ev, "content_hash": "48c65c638aceb5de" }),
            )
            .await;
            assert_eq!(s, axum::http::StatusCode::BAD_REQUEST, "{ev}: {body}");
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("transaction_signature"),
                "{body}"
            );
        }
        for bad in ["5xSig", "0OIl", &"1".repeat(88)] {
            let (s, body) = post_json(
                &app,
                "/audit/event",
                None,
                serde_json::json!({
                    "event_type": "submission",
                    "content_hash": "48c65c638aceb5de",
                    "transaction_signature": bad,
                }),
            )
            .await;
            assert_eq!(s, axum::http::StatusCode::BAD_REQUEST, "{bad}: {body}");
            let (s, body) = post_json(
                &app,
                "/verify/execution",
                None,
                serde_json::json!({ "signature": bad }),
            )
            .await;
            assert_eq!(s, axum::http::StatusCode::BAD_REQUEST, "{bad}: {body}");
        }
        let (s, body) = post_json(
            &app,
            "/audit/event",
            None,
            serde_json::json!({ "event_type": "signing", "content_hash": "48c65c638aceb5de" }),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The L8 row Graphite writes is marked as its own observation and does
    /// not make a later caller confirmation a duplicate.
    #[tokio::test]
    async fn graphite_observed_rows_are_marked_and_are_not_duplicates_of_reports() {
        let (state, dir) = test_state();
        let log = state.audit.clone().unwrap();
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        let signature = sig(9);
        assert!(log.append_lifecycle(&LifecycleEventRecord {
            event_type: LifecycleEvent::Confirmation,
            timestamp: crate::durable::now_utc_rfc3339(),
            content_hash: "aaaaaaaaaaaaaaaa".to_string(),
            verdict_on_record: None,
            verdict_on_record_key: None,
            transaction_sha256: None,
            audit_trail_id: Some("gr-aaaaaaaaaaaaaaaa".to_string()),
            transaction_signature: Some(signature.clone()),
            reported_by: None,
            detail: Some("L8 reconciliation: ApprovedAndExecuted".to_string()),
            observed_by_graphite: true,
            sequence_anomalies: Vec::new(),
        }));
        let app = build_app(state, vec![]);
        let (s, body) = post_json(
            &app,
            "/audit/event",
            None,
            serde_json::json!({
                "event_type": "confirmation",
                "content_hash": "aaaaaaaaaaaaaaaa",
                "audit_trail_id": "gr-aaaaaaaaaaaaaaaa",
                "transaction_signature": signature,
            }),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::OK, "{body}");
        let a: Vec<String> = body["sequence_anomalies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(!a.iter().any(|x| x.starts_with("duplicate")), "{a:?}");
        // The row on disk says who observed it.
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        assert!(
            contents.contains("\"observed_by_graphite\":true"),
            "{contents}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Audit 2026-10-20: server findings ───────────────────────────────────

    /// L2: `GRAPHITE_CORS_ORIGINS=*` reached tower-http's origin list, which
    /// panics on a wildcard, so the server died at startup with a backtrace.
    /// It is a configuration error now, and so is an entry that is not an
    /// origin (it was dropped or kept unmatchable, silently).
    #[test]
    fn cors_wildcards_and_non_origins_are_configuration_errors() {
        assert_eq!(cors_origins_from(None).unwrap(), Vec::<HeaderValue>::new());
        assert!(cors_origins_from(Some("  ")).unwrap().is_empty());
        let ok =
            cors_origins_from(Some("https://dash.example.com, http://localhost:5173,")).unwrap();
        assert_eq!(ok.len(), 2);
        for bad in [
            "*",
            "https://dash.example.com,*",
            "https://dash.example.com/",
            "https://dash.example.com/path",
            "dash.example.com",
            "null",
            "ftp://dash.example.com",
            "https://",
            "https://*.example.com",
        ] {
            let e = cors_origins_from(Some(bad)).unwrap_err();
            assert!(e.contains("REFUSING TO START"), "{bad}: {e}");
        }
        // What the refused value would have done: building the layer with a
        // wildcard in the list panics. The parser keeps it from getting there.
        let panicked = std::panic::catch_unwind(|| {
            tower_http::cors::CorsLayer::new().allow_origin(vec![HeaderValue::from_static("*")])
        })
        .is_err();
        assert!(
            panicked,
            "precondition: tower-http panics on a listed wildcard"
        );
    }

    /// Audit 2026-10-20: the numeric and boolean settings fell back to their
    /// defaults on a value that did not parse (`GRAPHITE_TRUST_PROXY=yes` was
    /// 0, `GRAPHITE_MAX_CONCURRENT=3O` was 32, `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=" 1"`
    /// was off). Each refuses to start now, naming the variable.
    #[test]
    fn settings_that_do_not_parse_refuse_to_start() {
        assert_eq!(trust_proxy_hops_from(None), Ok(0));
        assert_eq!(trust_proxy_hops_from(Some("")), Ok(0));
        assert_eq!(trust_proxy_hops_from(Some(" TRUE ")), Ok(1));
        assert_eq!(trust_proxy_hops_from(Some("false")), Ok(0));
        assert_eq!(trust_proxy_hops_from(Some(" 2 ")), Ok(2));
        for bad in ["yes", "-1", "256", "1.5", "on"] {
            assert!(trust_proxy_hops_from(Some(bad)).is_err(), "{bad}");
        }

        let none = |_: &str| None;
        let d = Limits::from_lookup(none, 0).unwrap();
        assert_eq!(d.inflight_limit, DEFAULT_MAX_CONCURRENT_VERIFICATIONS);
        assert_eq!(d.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(d.max_per_peer, DEFAULT_MAX_CONNECTIONS_PER_PEER);
        assert_eq!(d.connection_lifetime, DEFAULT_CONNECTION_LIFETIME);
        assert_eq!(d.rotate_bytes, crate::durable::DEFAULT_ROTATE_BYTES);
        assert_eq!(d.max_archives, 0);
        assert_eq!(
            Limits::from_lookup(none, 1).unwrap().max_per_peer,
            0,
            "behind a proxy the default is no per-peer cap"
        );
        let with = |name: &'static str, value: &'static str| {
            move |k: &str| (k == name).then(|| value.to_string())
        };
        assert_eq!(
            Limits::from_lookup(with("GRAPHITE_MAX_CONNECTIONS_PER_IP", "0"), 0)
                .unwrap()
                .max_per_peer,
            0
        );
        assert_eq!(
            Limits::from_lookup(with("GRAPHITE_MAX_CONCURRENT", " 8 "), 0)
                .unwrap()
                .inflight_limit,
            8
        );
        for (name, value) in [
            ("GRAPHITE_AUDIT_ROTATE_BYTES", "64MB"),
            ("GRAPHITE_AUDIT_MAX_ARCHIVES", "-1"),
            ("GRAPHITE_MAX_CONCURRENT", "3O"),
            ("GRAPHITE_MAX_CONCURRENT", "0"),
            ("GRAPHITE_MAX_CONNECTIONS", "0"),
            ("GRAPHITE_MAX_CONNECTIONS", "lots"),
            ("GRAPHITE_MAX_CONNECTIONS_PER_IP", "ten"),
            ("GRAPHITE_CONNECTION_LIFETIME_SECS", "0"),
            ("GRAPHITE_CONNECTION_LIFETIME_SECS", "2m"),
        ] {
            let e = Limits::from_lookup(with(name, value), 0).unwrap_err();
            assert!(e.contains(name), "{name}={value}: {e}");
        }

        let policy = |name: &'static str, value: &'static str| {
            OperatorPolicy::from_lookup(move |k: &str| (k == name).then(|| value.to_string()))
        };
        assert!(
            policy("GRAPHITE_ALLOW_PERMISSIVE_PROFILES", " 1")
                .unwrap()
                .allow_permissive_profiles,
            "trimmed, as every other switch is"
        );
        for name in [
            "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
            "GRAPHITE_ALLOW_DURABLE_NONCE",
            "GRAPHITE_QUARANTINE_ON_UPGRADE",
            "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
            "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
            "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
        ] {
            assert!(policy(name, "yes").is_err(), "{name}=yes");
        }
        // Round 32: the three relaxations are off unless set, and each reads
        // its own variable.
        let unset = policy("GRAPHITE_UNRELATED", "1").unwrap();
        assert!(
            !unset.allow_unreadable_value_declarations
                && !unset.allow_signer_lamports_outside_declared_debit
                && !unset.allow_unbounded_withdrawals
        );
        assert!(
            policy("GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS", "true")
                .unwrap()
                .allow_unreadable_value_declarations
        );
        assert!(
            policy("GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT", "1")
                .unwrap()
                .allow_signer_lamports_outside_declared_debit
        );
        assert!(
            policy("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS", "1")
                .unwrap()
                .allow_unbounded_withdrawals
        );
        // Round 30 (G-02): retired, and refused whatever its value, so an
        // operator who relied on it learns that it no longer exists.
        for value in ["1", "0", "true", "yes"] {
            let e = policy("GRAPHITE_LEARN_FROM_POLICY_REFUSALS", value).unwrap_err();
            assert!(e.contains("removed in Round 30"), "{value}: {e}");
        }
        assert!(
            policy("GRAPHITE_LEARN_FROM_POLICY_REFUSALS", "  ").is_ok(),
            "an empty value is an unset one, as for every other switch"
        );
        assert!(policy("GRAPHITE_WALLET_PROFILE", "treasry").is_err());
    }

    /// The `Host` names a keyless instance answers to.
    #[test]
    fn loopback_hosts_are_recognised() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:7331",
            "127.1.2.3:80",
            "localhost",
            "LOCALHOST:7331",
            "app.localhost:5173",
            "localhost.",
            "[::1]",
            "[::1]:7331",
        ] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in [
            "attacker.example",
            "attacker.example:7331",
            "127.0.0.1.attacker.example",
            "localhost.attacker.example",
            "10.0.0.1",
            "[::2]:7331",
            "[::1]x",
            "0.0.0.0",
            "localhost:http",
            "",
        ] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }

    /// L8: a keyless (dev-mode) instance is bound to loopback, but a web page
    /// in the operator's browser reaches it through DNS rebinding with its
    /// own name in `Host`. It is refused; loopback names and a request with
    /// no `Host` are not. With a key configured, the key is the control.
    #[tokio::test]
    async fn dev_mode_refuses_requests_addressed_to_another_host() {
        use axum::body::Body;
        use tower::ServiceExt;
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let get = |path: &str, host: Option<&str>, key: Option<&str>| {
            let mut b = axum::http::Request::builder().uri(path);
            if let Some(h) = host {
                b = b.header(header::HOST, h);
            }
            if let Some(k) = key {
                b = b.header(header::AUTHORIZATION, format!("Bearer {k}"));
            }
            let mut req = b.body(Body::empty()).unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        };
        let (state, _dir) = test_state();
        assert!(state.api_key.is_none(), "precondition: keyless");
        let app = build_app(state, vec![]);
        for path in ["/health", "/api/graph", "/manifests"] {
            let resp = app
                .clone()
                .oneshot(get(path, Some("attacker.example:7331"), None))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{path} answered a rebound name"
            );
        }
        for host in [
            Some("127.0.0.1:7331"),
            Some("localhost:7331"),
            Some("[::1]:7331"),
            None,
        ] {
            let resp = app
                .clone()
                .oneshot(get("/api/graph", host, None))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{host:?}");
        }

        let (mut state, _dir) = test_state();
        state.api_key = Some(Arc::new(VERIFY_TEST_KEY.to_string()));
        let app = build_app(state, vec![]);
        let resp = app
            .oneshot(get(
                "/api/graph",
                Some("graphite.internal:7331"),
                Some(VERIFY_TEST_KEY),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a keyed instance serves any name"
        );
    }

    /// L5: the 422 text quotes the offending input; it was logged and
    /// returned whole, and counted nowhere. It is bounded like the audit
    /// copy and counted as a failed verification request.
    #[tokio::test]
    async fn a_422_is_bounded_and_counted() {
        let (state, _dir) = test_state();
        let requests = Arc::clone(&state.metrics.verify_requests);
        let errors = Arc::clone(&state.metrics.verify_errors);
        let app = build_app(state, vec![]);
        let field = "x".repeat(20_000);
        let (status, body) =
            post_json(&app, "/verify", None, serde_json::json!({ field: 1 })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let text = body["error"].as_str().unwrap();
        assert!(
            text.chars().count() <= MAX_REJECTION_TEXT_CHARS + 64,
            "{} chars returned",
            text.chars().count()
        );
        assert!(text.contains("[truncated,"), "{text}");
        assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(errors.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(bounded_rejection_text("short"), "short");
    }

    /// `/verify/execution`, `/audit/event` and `/admin/quarantine` refused
    /// malformed requests with no counter and no audit row; probing them left
    /// no trace where `/verify`'s probes land. Each refusal is counted and on
    /// the trail now, naming its route.
    #[tokio::test]
    async fn malformed_requests_to_the_other_routes_are_counted_and_audited() {
        let (state, _dir, admin) = keyed_state();
        let log = state.audit.clone().unwrap();
        let rejections = Arc::clone(&state.metrics.request_rejections);
        let app = build_app(state, vec![]);

        let (s, _) = post_json(
            &app,
            "/verify/execution",
            Some(VERIFY_TEST_KEY),
            serde_json::json!({ "signature": "not-a-signature" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, body) = post_json(
            &app,
            "/audit/event",
            Some(VERIFY_TEST_KEY),
            serde_json::json!({ "event_type": "signing", "content_hash": "x".repeat(5000) }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        let (s, body) = post_json(
            &app,
            "/audit/event",
            Some(VERIFY_TEST_KEY),
            serde_json::json!({ "event_type": "not-an-event", "y".repeat(5000): 1 }),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().unwrap().chars().count() <= MAX_REJECTION_TEXT_CHARS + 64,
            "the 422 text is bounded on every route"
        );
        let (s, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(&admin),
            serde_json::json!({ "program_id": "not-a-program", "reason": "r" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        // Not a malformed request: refused for its credential, not counted here.
        let (s, _) = post_json(
            &app,
            "/admin/quarantine",
            Some(VERIFY_TEST_KEY),
            serde_json::json!({ "program_id": SYSTEM, "reason": "r" }),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        assert_eq!(rejections.load(std::sync::atomic::Ordering::Relaxed), 4);
        let (_, errors, _, total_errors) = log.read_tail_filtered(10, AuditSelector::All);
        assert_eq!(total_errors, 4, "{errors:?}");
        let routes: Vec<&str> = errors.iter().map(|e| e.instruction_name.as_str()).collect();
        assert_eq!(
            routes,
            [
                "POST /verify/execution",
                "POST /audit/event",
                "POST /audit/event",
                "POST /admin/quarantine"
            ]
        );
        assert_eq!(errors[2].status, 422);
        assert_eq!(errors[2].error_type, "JsonRejection");
        assert_eq!(errors[3].program_id, "not-a-program");
    }

    /// L7: `count` added the length of the CAPPED error list, so past
    /// `VIOLATIONS_CAP` error records it stopped growing.
    #[tokio::test]
    async fn policy_violations_count_is_the_whole_trail_past_the_cap() {
        let (state, _dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        for i in 0..VIOLATIONS_CAP + 7 {
            assert!(log.append_error(&crate::durable::AuditErrorRecord {
                timestamp: crate::durable::now_utc_rfc3339(),
                program_id: format!("probe-{i}"),
                instruction_name: "n/a".to_string(),
                error: "bad".to_string(),
                error_type: "bad_input".to_string(),
                status: 400,
            }));
        }
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/policy-violations").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["error_violations"].as_array().unwrap().len(),
            VIOLATIONS_CAP
        );
        assert_eq!(json["count"], VIOLATIONS_CAP + 7);
        assert_eq!(json["error_count"], VIOLATIONS_CAP + 7);
        assert_eq!(json["violation_count"], 0);
    }

    /// Both halves' true totals are reported apart, and `count` is their sum.
    #[tokio::test]
    async fn policy_violations_report_each_total() {
        let (state, _dir) = test_state();
        let log = state.audit.as_ref().unwrap();
        for i in 0..3 {
            let mut r = verification_row(&format!("{i:016x}"), false);
            r.audit_trail_id = format!("gr-v{i}");
            assert!(log.append(&r));
        }
        assert!(log.append(&verification_row("aaaaaaaaaaaaaaaa", true)));
        assert!(log.append_error(&crate::durable::AuditErrorRecord {
            timestamp: crate::durable::now_utc_rfc3339(),
            program_id: "probe".to_string(),
            instruction_name: "n/a".to_string(),
            error: "bad".to_string(),
            error_type: "bad_input".to_string(),
            status: 400,
        }));
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/policy-violations").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["violation_count"], 3, "{json}");
        assert_eq!(json["error_count"], 1, "{json}");
        assert_eq!(json["count"], 4, "{json}");
    }

    /// `/api/protocols/top` returned a fixed 5 rows, so the dashboard could
    /// not show any other program's verification count. `?limit=` takes up
    /// to 500; the default is unchanged; `program_count` is the whole set.
    #[tokio::test]
    async fn top_protocols_takes_a_bounded_limit() {
        let (state, _dir) = test_state();
        let app = build_app(state, vec![]);
        let (status, json) = get_json(&app, "/api/protocols/top").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["top"].as_array().unwrap().len(), DEFAULT_TOP_PROTOCOLS);
        let total = json["program_count"].as_u64().unwrap() as usize;
        assert!(
            total > 20,
            "precondition: more programs than the default ({total})"
        );

        let (status, json) = get_json(&app, "/api/protocols/top?limit=20").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["top"].as_array().unwrap().len(), 20);
        let (_, json) = get_json(&app, "/api/protocols/top?limit=500").await;
        assert_eq!(
            json["top"].as_array().unwrap().len(),
            total.min(MAX_TOP_PROTOCOLS)
        );
        for bad in ["limit=0", "limit=501", "limit=abc", "limit="] {
            let (status, _) = get_json(&app, &format!("/api/protocols/top?{bad}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        assert_eq!(
            top_protocols_limit(Some("other=1")),
            Ok(DEFAULT_TOP_PROTOCOLS)
        );
    }

    /// `/health` answers without a key, and listed the program ids of frozen
    /// baselines. It carries the count; the list is behind the key.
    #[tokio::test]
    async fn frozen_baselines_are_counted_on_health_and_listed_behind_the_key() {
        let (state, _dir, _admin) = keyed_state();
        let app = build_app(state, vec![]);
        let (status, health) = get_json(&app, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(health["frozen_baseline_count"], 0);
        assert!(health.get("frozen_baselines").is_none(), "{health}");
        let (status, _) = get_json(&app, "/api/frozen-baselines").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        use axum::body::Body;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .uri("/api/frozen-baselines")
            .header(header::AUTHORIZATION, format!("Bearer {VERIFY_TEST_KEY}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:9999".parse::<SocketAddr>().unwrap()));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["count"], 0);
        assert!(body["frozen_baselines"].as_array().unwrap().is_empty());
    }

    /// Two quarantines of one program at once each read "not quarantined"
    /// and each appended a record. The handler takes them one at a time.
    #[tokio::test]
    async fn concurrent_quarantines_of_one_program_append_one_record() {
        let (state, _dir, admin) = keyed_state();
        let core = state.core.clone();
        let app = build_app(state, vec![]);
        let body = serde_json::json!({
            "program_id": SYSTEM,
            "reason": QUARANTINE_RACE_WINDOW_REASON,
        });
        let (a, b) = tokio::join!(
            post_json(&app, "/admin/quarantine", Some(&admin), body.clone()),
            post_json(&app, "/admin/quarantine", Some(&admin), body.clone()),
        );
        assert_eq!(a.0, StatusCode::OK, "{}", a.1);
        assert_eq!(b.0, StatusCode::OK, "{}", b.1);
        let quarantines = core
            .behavior_history(SYSTEM)
            .iter()
            .filter(|r| r.quarantined)
            .count();
        assert_eq!(quarantines, 1, "two quarantine records for one action");
        assert!(
            a.1["already_quarantined"] == true || b.1["already_quarantined"] == true,
            "{} / {}",
            a.1,
            b.1
        );
    }

    /// The L8 row stored the caller's `content_hash` untrimmed, though it was
    /// validated and looked up trimmed, so the row never matched the hash.
    #[tokio::test]
    async fn the_l8_row_carries_the_trimmed_content_hash() {
        let (state, dir) = test_state();
        let app = build_app(state, vec![]);
        let signature = bs58::encode([0x22u8; 64]).into_string();
        let (s, body) = post_json(
            &app,
            "/verify/execution",
            None,
            serde_json::json!({ "signature": signature, "content_hash": "  bbbbbbbbbbbbbbbb  " }),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let contents = std::fs::read_to_string(audit_path(&dir)).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(row["content_hash"], "bbbbbbbbbbbbbbbb", "{row}");
    }
}

#[cfg(test)]
mod request_path_cost {
    use super::*;

    /// Round 11: `AppState` is cloned on every `State` extraction and by every
    /// `from_fn_with_state` middleware. Until Round 11 that deep-copied the
    /// whole manifest registry and the community registry engine — about
    /// 15 ms per clone on the reference machine, four clones per request, so
    /// `/health` answered in ~100 ms.
    ///
    /// Checked structurally, not by the clock (2026-09-29 audit, A6-11: a
    /// wall-clock bound on a shared CI runner is a flake waiting to happen):
    /// every clone must share the SAME core, registry engine and permit pool
    /// as the original — a deep copy is a different allocation.
    #[test]
    fn app_state_clone_is_a_reference_count_not_a_deep_copy() {
        let (state, dir) = tests::test_state();
        let mut keep = Vec::with_capacity(1000);
        for _ in 0..1000 {
            keep.push(state.clone());
        }
        for clone in &keep {
            assert!(
                Arc::ptr_eq(&clone.core, &state.core),
                "the core was deep-copied"
            );
            assert!(
                Arc::ptr_eq(&clone.registry_engine, &state.registry_engine),
                "the registry engine was deep-copied"
            );
            assert!(
                Arc::ptr_eq(&clone.inflight, &state.inflight),
                "the permit pool was copied: each clone would admit its own requests"
            );
        }
        assert_eq!(Arc::strong_count(&state.core), 1001);
        drop(keep);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same, end to end: a bound server answers `/health` in single-digit
    /// milliseconds, sequentially, on loopback. Generous bound (50 ms) so
    /// a loaded CI runner passes; the regression this guards was 100 ms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_answers_in_milliseconds_on_loopback() {
        let (state, dir) = tests::test_state();
        let app = build_app(state, vec![]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::new();
        // Warm the connection, then time twenty sequential round trips.
        let _ = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap();
        let t = std::time::Instant::now();
        for _ in 0..20 {
            let r = client
                .get(format!("http://{addr}/health"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), reqwest::StatusCode::OK);
            let _ = r.bytes().await.unwrap();
        }
        let per_request = t.elapsed() / 20;
        eprintln!("/health: {per_request:?} per sequential request");
        assert!(
            per_request < Duration::from_millis(50),
            "/health took {per_request:?} per request; the request path has grown a per-request cost"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Round 11: a refusal issued before the body was read (401 here, and
    /// 429 / 503 by the same helper) must still be READABLE by the client.
    /// Without draining, the server closes with unread bytes in the socket,
    /// the kernel answers with RST, and a client still writing its body sees
    /// a reset instead of the status. The client here is a raw socket that
    /// sends the headers and the first part of a 600 KB body, pauses, then
    /// sends the rest — the shape of a real upload on a real network, and
    /// exactly the interleaving a keep-alive client library cannot be made
    /// to produce on demand. 600 KB is under the 1 MiB limit, so the body is
    /// a legal one the server merely declined.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn early_refusals_drain_the_body_so_the_status_is_readable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut state, dir) = tests::test_state();
        state.api_key = Some(Arc::new("k3y-k3y-k3y-k3y-k3y-k3y-k3y-k3y-".to_string()));
        state.rate = RateLimiter::with_capacity(16, 1.0);
        let app = build_app(state, vec![]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // One slow upload; returns the status line the client could read, or
        // the error it got instead.
        async fn slow_post(addr: SocketAddr, key: &str) -> Result<String, String> {
            let body = format!("{{\"pad\":\"{}\"}}", "x".repeat(600 * 1024));
            let head = format!(
                "POST /verify HTTP/1.1
Host: {addr}
Authorization: Bearer {key}
Content-Type: application/json
Content-Length: {}
Connection: close

",
                body.len()
            );
            let mut sock = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            sock.write_all(head.as_bytes())
                .await
                .map_err(|e| format!("head: {e}"))?;
            sock.write_all(&body.as_bytes()[..64 * 1024])
                .await
                .map_err(|e| format!("first part: {e}"))?;
            tokio::time::sleep(Duration::from_millis(400)).await;
            // The rest may or may not be accepted; what matters is what the
            // client can READ afterwards.
            let _ = sock.write_all(&body.as_bytes()[64 * 1024..]).await;
            let mut out = Vec::new();
            match tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut out)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if !out.is_empty() => {
                    // A reset after the whole response arrived still counts as
                    // readable; a reset before it does not.
                    let _ = e;
                }
                Ok(Err(e)) => return Err(format!("read: {e}")),
                Err(_) => return Err("read: timed out".to_string()),
            }
            let text = String::from_utf8_lossy(&out);
            text.lines()
                .next()
                .map(str::to_string)
                .ok_or_else(|| "read: empty response".to_string())
        }

        let status = slow_post(addr, "wrong-key-wrong-key-wrong-key-wrong")
            .await
            .unwrap_or_else(|e| panic!("the 401 must be readable, not a reset: {e}"));
        assert!(status.starts_with("HTTP/1.1 401"), "{status}");

        // The one token went to the 401 above; the next slow upload arrives
        // before it refills and must read a 429, not a reset.
        let mut saw_429 = false;
        for attempt in 0..6 {
            let status = slow_post(addr, "k3y-k3y-k3y-k3y-k3y-k3y-k3y-k3y-")
                .await
                .unwrap_or_else(|e| {
                    panic!("attempt {attempt}: a refusal must be readable, not a reset: {e}")
                });
            if status.starts_with("HTTP/1.1 429") {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "the bucket must have run out within six requests");
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Round 30 (§4.6): every route the router serves, held to its privilege,
/// method, body bound and rate limit by one table. A route added to
/// `build_app` and not to `ROUTES` fails `the_table_names_every_route`, so a
/// new endpoint cannot ship without a decision about who may call it.
#[cfg(test)]
mod route_surface {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Needs {
        /// Open: load balancers probe it.
        Nothing,
        /// Reports only: the read key (`GRAPHITE_READ_API_KEY`) or the
        /// verify key.
        ReadKey,
        /// Verifies or records: the verify key (`GRAPHITE_API_KEY`) only.
        VerifyKey,
        /// The operator key (`GRAPHITE_ADMIN_API_KEY`) and only it.
        OperatorKey,
    }

    /// (method, path, privilege). Kept in step with `build_app`.
    const ROUTES: &[(&str, &str, Needs)] = &[
        ("POST", "/verify", Needs::VerifyKey),
        ("GET", "/health", Needs::Nothing),
        ("GET", "/metrics", Needs::ReadKey),
        ("GET", "/manifests", Needs::ReadKey),
        ("POST", "/audit/event", Needs::VerifyKey),
        ("POST", "/verify/execution", Needs::VerifyKey),
        ("POST", "/admin/quarantine", Needs::OperatorKey),
        ("GET", "/admin/quarantine", Needs::OperatorKey),
        ("GET", "/api/graph", Needs::ReadKey),
        ("GET", "/api/confidence-history", Needs::ReadKey),
        ("GET", "/api/policy-violations", Needs::ReadKey),
        ("GET", "/api/protocols/top", Needs::ReadKey),
        ("GET", "/api/registry", Needs::ReadKey),
        ("GET", "/api/frozen-baselines", Needs::ReadKey),
    ];

    const VERIFY: &str = "route-surface-verify-key";
    const OPERATOR: &str = "route-surface-operator-key";
    const READ: &str = "route-surface-read-key";

    fn keyed(rate: f64) -> (AppState, std::path::PathBuf) {
        let (mut state, dir) = super::tests::test_state();
        state.api_key = Some(Arc::new(VERIFY.to_string()));
        state.admin_key = Some(Arc::new(OPERATOR.to_string()));
        state.read_key = Some(Arc::new(READ.to_string()));
        state.rate = RateLimiter::new(rate);
        (state, dir)
    }

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        keys: &[&str],
        body: Vec<u8>,
    ) -> (StatusCode, String) {
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("host", "127.0.0.1");
        for k in keys {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        let mut req = b.body(Body::from(body)).unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4 << 20)
            .await
            .unwrap_or_default();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn denied(s: StatusCode) -> bool {
        s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN
    }

    /// Every `.route("…")` in `build_app` is in `ROUTES`, and every path in
    /// `ROUTES` is routed: the table cannot drift from the router.
    #[test]
    fn the_table_names_every_route() {
        let src = include_str!("server.rs");
        let start = src.find("fn build_app(").expect("build_app");
        let end = start + src[start..].find("\n}\n").expect("end of build_app");
        let mut routed: Vec<&str> = src[start..end]
            .split(".route(")
            .skip(1)
            .filter_map(|s| s.trim_start().strip_prefix('"'))
            .filter_map(|s| s.split('"').next())
            .collect();
        routed.sort();
        routed.dedup();
        let mut tabled: Vec<&str> = ROUTES.iter().map(|(_, p, _)| *p).collect();
        tabled.sort();
        tabled.dedup();
        assert_eq!(routed, tabled, "build_app's routes and ROUTES differ");
    }

    #[tokio::test]
    async fn each_route_answers_only_to_its_privilege() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        for &(method, path, needs) in ROUTES {
            let body = if method == "POST" {
                b"{}".to_vec()
            } else {
                vec![]
            };
            let (none, _) = call(&app, method, path, &[], body.clone()).await;
            let (verify, _) = call(&app, method, path, &[VERIFY], body.clone()).await;
            let (operator, _) = call(&app, method, path, &[OPERATOR], body.clone()).await;
            let (read, _) = call(&app, method, path, &[READ], body.clone()).await;
            match needs {
                Needs::Nothing => {
                    assert_eq!(none, StatusCode::OK, "{method} {path} without a key");
                }
                Needs::ReadKey | Needs::VerifyKey => {
                    assert_eq!(
                        none,
                        StatusCode::UNAUTHORIZED,
                        "{method} {path} without a key"
                    );
                    assert!(
                        !denied(verify),
                        "{method} {path} with the verify key: {verify}"
                    );
                    assert_eq!(
                        operator,
                        StatusCode::UNAUTHORIZED,
                        "{method} {path}: the operator key is not a verify key"
                    );
                    if needs == Needs::ReadKey {
                        assert!(!denied(read), "{method} {path} with the read key: {read}");
                    } else {
                        assert_eq!(
                            read,
                            StatusCode::UNAUTHORIZED,
                            "{method} {path}: the read key must not verify or record"
                        );
                    }
                }
                Needs::OperatorKey => {
                    assert!(denied(none), "{method} {path} without a key: {none}");
                    assert_eq!(
                        verify,
                        StatusCode::UNAUTHORIZED,
                        "{method} {path}: the verify key must not open the operator surface"
                    );
                    assert_eq!(
                        read,
                        StatusCode::UNAUTHORIZED,
                        "{method} {path}: the read key must not open the operator surface"
                    );
                    assert!(
                        !denied(operator),
                        "{method} {path} with the operator key: {operator}"
                    );
                }
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two Authorization headers are refused even when both carry the right
    /// key, on every authenticated route.
    #[tokio::test]
    async fn two_authorization_headers_are_refused() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        for &(method, path, needs) in ROUTES {
            if needs == Needs::Nothing {
                continue;
            }
            let key = if needs == Needs::OperatorKey {
                OPERATOR
            } else {
                VERIFY
            };
            let body = if method == "POST" {
                b"{}".to_vec()
            } else {
                vec![]
            };
            for keys in [[key, key], [key, "wrong"], ["wrong", key]] {
                let (status, _) = call(&app, method, path, &keys, body.clone()).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {keys:?}");
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Spellings of the operator path that are not the route never reach an
    /// operator handler with the verify key.
    #[tokio::test]
    async fn no_spelling_of_an_operator_path_opens_it_to_the_verify_key() {
        let (state, dir) = keyed(1000.0);
        let core = Arc::clone(&state.core);
        let app = build_app(state, vec![]);
        for path in [
            "//admin/quarantine",
            "/admin//quarantine",
            "/admin/quarantine/",
            "/ADMIN/quarantine",
            "/Admin/Quarantine",
            "/%61dmin/quarantine",
            "/admin/%71uarantine",
            "/./admin/quarantine",
            "/api/../admin/quarantine",
            "/admin/quarantine?x=1",
        ] {
            for method in ["GET", "POST"] {
                let (status, body) = call(
                    &app,
                    method,
                    path,
                    &[VERIFY],
                    br#"{"program_id":"11111111111111111111111111111111","reason":"x"}"#.to_vec(),
                )
                .await;
                assert!(
                    !status.is_success(),
                    "{method} {path} answered {status} to the verify key: {body}"
                );
            }
        }
        assert!(
            core.quarantined_programs().is_empty(),
            "nothing was quarantined through the verify key"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The wrong method is refused, never served.
    #[tokio::test]
    async fn the_wrong_method_is_refused() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        for &(method, path, needs) in ROUTES {
            // With the route's own key, so what answers is the method check
            // and not authentication (which also refuses, earlier).
            let key = if needs == Needs::OperatorKey {
                OPERATOR
            } else {
                VERIFY
            };
            let other_read = if method == "GET" { "POST" } else { "GET" };
            for other in ["PUT", "DELETE", "PATCH", other_read] {
                if ROUTES.iter().any(|(m, p, _)| *p == path && *m == other) {
                    continue;
                }
                let (status, _) = call(&app, other, path, &[key], vec![]).await;
                assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{other} {path}");
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A body past `MAX_BODY_SIZE` is refused on every route that takes one,
    /// before a handler sees it.
    #[tokio::test]
    async fn every_body_is_bounded() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        let big = vec![b' '; MAX_BODY_SIZE + 1];
        for &(method, path, needs) in ROUTES {
            if method != "POST" {
                continue;
            }
            let key = if needs == Needs::OperatorKey {
                OPERATOR
            } else {
                VERIFY
            };
            let (status, _) = call(&app, method, path, &[key], big.clone()).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {path}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every route but `/health` is rate limited, and the limit is charged
    /// before authentication: an unauthenticated flood still runs out.
    #[tokio::test]
    async fn every_route_but_health_is_rate_limited() {
        for &(method, path, needs) in ROUTES {
            let (state, dir) = keyed(0.1);
            let app = build_app(state, vec![]);
            let body = if method == "POST" {
                b"{}".to_vec()
            } else {
                vec![]
            };
            let mut statuses = Vec::new();
            for _ in 0..3 {
                statuses.push(call(&app, method, path, &[], body.clone()).await.0);
            }
            if needs == Needs::Nothing {
                assert!(
                    statuses.iter().all(|s| *s == StatusCode::OK),
                    "{path} must never be rate limited: {statuses:?}"
                );
            } else {
                assert!(
                    statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
                    "{method} {path}: {statuses:?}"
                );
            }
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// `/health` answers without a key, so it carries nothing an anonymous
    /// caller should learn: no key, no data path, no RPC URL, no program id.
    #[tokio::test]
    async fn health_says_nothing_sensitive() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        let (status, body) = call(&app, "GET", "/health", &[], vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let dir_text = dir.to_string_lossy().to_string();
        for secret in [VERIFY, OPERATOR, dir_text.as_str(), "http://", "https://"] {
            assert!(!body.contains(secret), "/health carries {secret:?}: {body}");
        }
        assert!(
            !body.contains("11111111111111111111111111111111"),
            "/health names a program: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["l8_assurance"]["high_assurance"], false);
        assert!(v["l8_assurance"]["witness_independent"].is_null());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `/metrics` is behind the verify key and prints neither key.
    #[tokio::test]
    async fn metrics_print_no_key() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        let (status, body) = call(&app, "GET", "/metrics", &[VERIFY], vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains(VERIFY) && !body.contains(OPERATOR));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A JSON body that nests past serde's recursion limit, repeats a field,
    /// or spells a field in another case is refused, not half-read.
    #[tokio::test]
    async fn ambiguous_or_hostile_json_is_refused() {
        let (state, dir) = keyed(1000.0);
        let app = build_app(state, vec![]);
        let nested = format!(
            r#"{{"proposed_intent":{}1{}}}"#,
            "[".repeat(4096),
            "]".repeat(4096)
        );
        let sig = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
        let duplicate = format!(r#"{{"signature":"{sig}","signature":"{sig}"}}"#);
        let cased = format!(r#"{{"Signature":"{sig}"}}"#);
        for (path, body) in [
            ("/verify", nested.clone()),
            ("/verify/execution", nested),
            ("/verify/execution", duplicate),
            ("/verify/execution", cased),
        ] {
            let (status, text) = call(&app, "POST", path, &[VERIFY], body.into_bytes()).await;
            assert!(
                status.is_client_error() && status != StatusCode::UNAUTHORIZED,
                "{path}: {status} {text}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Dev mode (no key) answers only to a single loopback Host; two Host
    /// headers are not a loopback request.
    #[tokio::test]
    async fn dev_mode_refuses_two_host_headers() {
        let (state, dir) = super::tests::test_state();
        let app = build_app(state, vec![]);
        let mut req = axum::http::Request::builder()
            .uri("/api/graph")
            .header("host", "127.0.0.1")
            .header("host", "evil.example")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Behind one trusted proxy the client is the entry the proxy appended,
    /// however the client shapes its own part: extra lines, empty entries,
    /// bytes that are not ASCII, a zone id, a port.
    #[test]
    fn the_forwarded_client_is_the_proxy_appended_entry() {
        let peer: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let ip = |lines: &[&[u8]]| {
            let mut b = axum::http::Request::builder().uri("/verify");
            for l in lines {
                b = b.header(
                    "x-forwarded-for",
                    axum::http::HeaderValue::from_bytes(l).unwrap(),
                );
            }
            client_ip(&b.body(Body::empty()).unwrap(), peer, 1)
        };
        let real: IpAddr = "198.51.100.9".parse().unwrap();
        for lines in [
            vec![b"198.51.100.9".as_slice()],
            vec![b"1.2.3.4", b"198.51.100.9"],
            vec![b"1.2.3.4, 5.6.7.8", b"198.51.100.9"],
            vec![b"1.2.3.4,,, ,198.51.100.9"],
            vec![b"\xff\xfe junk, 198.51.100.9"],
            vec![b"fe80::1%eth0, 198.51.100.9"],
            vec![b"1.2.3.4, 198.51.100.9:4711"],
        ] {
            assert_eq!(ip(&lines), real, "{lines:?}");
        }
        // The proxy-appended position unparseable: the shared unattributed
        // bucket, never the proxy's peer bucket and never a caller-chosen one.
        for lines in [
            vec![b"198.51.100.9, not-an-ip".as_slice()],
            vec![b"198.51.100.9, fe80::1%eth0"],
        ] {
            assert_eq!(ip(&lines), UNATTRIBUTED_CLIENT, "{lines:?}");
        }
    }

    /// The read key opens no method but GET, on no route but the read ones,
    /// however the request is spelled.
    #[tokio::test]
    async fn the_read_key_cannot_verify_record_or_act() {
        let (state, dir) = keyed(1000.0);
        let core = Arc::clone(&state.core);
        let app = build_app(state, vec![]);
        for (method, path) in [
            ("POST", "/verify"),
            ("POST", "/verify/execution"),
            ("POST", "/audit/event"),
            ("POST", "/admin/quarantine"),
            ("GET", "/admin/quarantine"),
            ("POST", "/api/graph"),
            ("PUT", "/metrics"),
        ] {
            let (status, body) = call(
                &app,
                method,
                path,
                &[READ],
                br#"{"program_id":"11111111111111111111111111111111","reason":"x"}"#.to_vec(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}: {body}");
        }
        assert!(core.quarantined_programs().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_read_key_is_its_own_long_secret() {
        let verify = "v".repeat(MIN_API_KEY_CHARS);
        let admin = "a".repeat(MIN_API_KEY_CHARS);
        let read = "r".repeat(MIN_API_KEY_CHARS);
        assert!(read_key_posture(None, Some(&verify), None)
            .unwrap()
            .is_none());
        assert!(read_key_posture(Some("  "), Some(&verify), None)
            .unwrap()
            .is_none());
        assert_eq!(
            read_key_posture(Some(&read), Some(&verify), Some(&admin))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(read.as_str())
        );
        // Short, equal to another key, or without a verify key at all.
        assert!(read_key_posture(Some("short"), Some(&verify), None).is_err());
        assert!(read_key_posture(Some(&verify), Some(&verify), None).is_err());
        assert!(
            read_key_posture(Some(&format!(" {admin} ")), Some(&verify), Some(&admin)).is_err()
        );
        assert!(read_key_posture(Some(&read), None, None).is_err());
    }

    #[test]
    fn high_assurance_needs_an_independent_attested_https_witness() {
        use crate::rpc_client::WitnessIndependence as W;
        let ok = Some(W::Distinct);
        let https = (Some("https"), Some("https"));
        let named = (Some("Helius"), Some("Triton"));
        assert_eq!(high_assurance_refusal(ok.as_ref(), named, https), None);
        // No witness.
        assert!(high_assurance_refusal(None, named, https).is_some());
        // Not independent.
        let same = Some(W::NotIndependent("same host".into()));
        assert!(high_assurance_refusal(same.as_ref(), named, https)
            .unwrap()
            .contains("same host"));
        // Plaintext on either side.
        for schemes in [(Some("http"), Some("https")), (Some("https"), Some("http"))] {
            assert!(high_assurance_refusal(ok.as_ref(), named, schemes).is_some());
        }
        // Providers unnamed, blank, or the same name in another case.
        for providers in [
            (None, Some("Triton")),
            (Some("Helius"), None),
            (Some("  "), Some("Triton")),
            (Some("Helius"), Some(" helius ")),
        ] {
            assert!(
                high_assurance_refusal(ok.as_ref(), providers, https).is_some(),
                "{providers:?}"
            );
        }
    }
}
