//! Bounded Open Ranking profile discovery.
//!
//! The provider returns derived ranking data only: pubkeys and scores. Raw
//! profile events are hydrated separately through the directory relay plane so
//! they still receive the normal Nostr signature, freshness, and host-safety
//! checks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use cgka_traits::app_components::reject_non_public_ip;
use reqwest::header::RETRY_AFTER;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};
use url::{Host, Url};

use crate::ids::parse_account_id_hex;

const VERTEX_OPEN_RANKING_SEARCH_URL: &str = "https://ranking.vertexlab.io/search/pubkeys";
const OPEN_RANKING_TIMEOUT: Duration = Duration::from_secs(5);
const OPEN_RANKING_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const OPEN_RANKING_MAX_QUERY_CHARS: usize = 512;
pub(crate) const OPEN_RANKING_RESULT_LIMIT: usize = 20;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RankedPubkey {
    pub(crate) account_id_hex: String,
    pub(crate) rank: f64,
}

#[derive(Serialize)]
struct SearchRequest<'a> {
    query: &'a str,
    limit: usize,
}

#[derive(Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Deserialize)]
struct SearchResult {
    pubkey: String,
    rank: f64,
}

/// Ask Vertex's Open Ranking provider for ranked pubkeys.
///
/// The entire operation, including DNS and any protocol-mandated `202` retry,
/// is bounded to five seconds. Results are normalized, deduplicated, and sorted
/// locally before they cross into directory search.
pub(crate) async fn search_vertex_pubkeys(query: &str) -> Result<Vec<RankedPubkey>, String> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(Vec::new());
    }
    if query.chars().count() > OPEN_RANKING_MAX_QUERY_CHARS {
        return Err("Open Ranking query exceeds the protocol limit".to_owned());
    }

    timeout(OPEN_RANKING_TIMEOUT, search_vertex_pubkeys_inner(query))
        .await
        .map_err(|_| "Open Ranking request timed out".to_owned())?
}

async fn search_vertex_pubkeys_inner(query: &str) -> Result<Vec<RankedPubkey>, String> {
    let url = Url::parse(VERTEX_OPEN_RANKING_SEARCH_URL)
        .map_err(|_| "Open Ranking provider URL is invalid".to_owned())?;
    let client = open_ranking_http_client(&url).await?;
    let request = SearchRequest {
        query,
        limit: OPEN_RANKING_RESULT_LIMIT,
    };

    loop {
        let mut response = client
            .post(url.clone())
            .json(&request)
            .send()
            .await
            .map_err(open_ranking_reqwest_error)?;
        if response.status() == reqwest::StatusCode::ACCEPTED {
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| "Open Ranking 202 response omitted Retry-After".to_owned())?;
            if retry_after == 0 {
                tokio::task::yield_now().await;
            } else {
                sleep(Duration::from_secs(retry_after)).await;
            }
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "Open Ranking request returned HTTP {}",
                response.status().as_u16()
            ));
        }

        let body = read_limited_body(&mut response, OPEN_RANKING_MAX_RESPONSE_BYTES).await?;
        let response: SearchResponse = serde_json::from_slice(&body)
            .map_err(|_| "Open Ranking response was invalid JSON".to_owned())?;
        let _cache_hint_seconds = response.ttl;
        return validate_ranked_pubkeys(response.results);
    }
}

fn validate_ranked_pubkeys(results: Vec<SearchResult>) -> Result<Vec<RankedPubkey>, String> {
    if results.len() > OPEN_RANKING_RESULT_LIMIT {
        return Err("Open Ranking response exceeded the requested limit".to_owned());
    }

    let mut ranks_by_pubkey = HashMap::<String, f64>::new();
    for result in results {
        let account_id_hex = parse_account_id_hex(&result.pubkey)
            .map_err(|_| "Open Ranking response contained an invalid pubkey".to_owned())?;
        if !result.rank.is_finite() {
            return Err("Open Ranking response contained an invalid rank".to_owned());
        }
        ranks_by_pubkey
            .entry(account_id_hex)
            .and_modify(|rank| *rank = rank.max(result.rank))
            .or_insert(result.rank);
    }

    let mut ranked = ranks_by_pubkey
        .into_iter()
        .map(|(account_id_hex, rank)| RankedPubkey {
            account_id_hex,
            rank,
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .rank
            .total_cmp(&left.rank)
            .then_with(|| left.account_id_hex.cmp(&right.account_id_hex))
    });
    Ok(ranked)
}

async fn open_ranking_http_client(url: &Url) -> Result<reqwest::Client, String> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Open Ranking provider URL is unsafe".to_owned());
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(OPEN_RANKING_TIMEOUT)
        .read_timeout(OPEN_RANKING_TIMEOUT)
        .timeout(OPEN_RANKING_TIMEOUT)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    if let Some((domain, addresses)) = resolve_open_ranking_host(url).await? {
        builder = builder.resolve_to_addrs(&domain, &addresses);
    }
    builder
        .build()
        .map_err(|_| "failed to build Open Ranking HTTP client".to_owned())
}

async fn resolve_open_ranking_host(url: &Url) -> Result<Option<(String, Vec<SocketAddr>)>, String> {
    let host = url
        .host()
        .ok_or_else(|| "Open Ranking provider URL is missing a host".to_owned())?;
    match host {
        Host::Domain(domain) => {
            let port = url
                .port_or_known_default()
                .ok_or_else(|| "Open Ranking provider URL is missing a port".to_owned())?;
            let addresses = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| "Open Ranking provider DNS lookup failed".to_owned())?
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err("Open Ranking provider DNS lookup returned no addresses".to_owned());
            }
            for address in &addresses {
                reject_non_public_ip(address.ip(), false)
                    .map_err(|_| "Open Ranking provider resolved unsafely".to_owned())?;
            }
            Ok(Some((domain.to_ascii_lowercase(), addresses)))
        }
        Host::Ipv4(address) => {
            reject_non_public_ip(address.into(), false)
                .map_err(|_| "Open Ranking provider address is unsafe".to_owned())?;
            Ok(None)
        }
        Host::Ipv6(address) => {
            reject_non_public_ip(address.into(), false)
                .map_err(|_| "Open Ranking provider address is unsafe".to_owned())?;
            Ok(None)
        }
    }
}

async fn read_limited_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("Open Ranking response exceeded the size limit".to_owned());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(open_ranking_reqwest_error)? {
        let remaining = max_bytes
            .checked_sub(body.len())
            .ok_or_else(|| "Open Ranking response exceeded the size limit".to_owned())?;
        if chunk.len() > remaining {
            return Err("Open Ranking response exceeded the size limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn open_ranking_reqwest_error(error: reqwest::Error) -> String {
    if let Some(status) = error.status() {
        format!("Open Ranking HTTP {}", status.as_u16())
    } else if error.is_timeout() {
        "Open Ranking request timed out".to_owned()
    } else if error.is_connect() {
        "Open Ranking connection failed".to_owned()
    } else if error.is_body() || error.is_decode() {
        "Open Ranking response body was invalid".to_owned()
    } else {
        "Open Ranking request failed".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranked_pubkeys_are_normalized_deduplicated_and_sorted() {
        let first = "11".repeat(32);
        let second = "22".repeat(32);
        let ranked = validate_ranked_pubkeys(vec![
            SearchResult {
                pubkey: first.clone(),
                rank: 0.25,
            },
            SearchResult {
                pubkey: second.clone(),
                rank: 0.5,
            },
            SearchResult {
                pubkey: first.clone(),
                rank: 0.75,
            },
        ])
        .unwrap();

        assert_eq!(
            ranked,
            vec![
                RankedPubkey {
                    account_id_hex: first,
                    rank: 0.75,
                },
                RankedPubkey {
                    account_id_hex: second,
                    rank: 0.5,
                },
            ]
        );
    }

    #[test]
    fn ranked_pubkeys_reject_invalid_provider_data() {
        let error = validate_ranked_pubkeys(vec![SearchResult {
            pubkey: "not-a-pubkey".to_owned(),
            rank: 1.0,
        }])
        .unwrap_err();
        assert_eq!(error, "Open Ranking response contained an invalid pubkey");
    }
}
