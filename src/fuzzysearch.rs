use std::{collections::HashMap, time::Duration};

use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct File {
    pub site_id: i64,
    pub site_id_str: String,

    pub url: String,
    pub filename: String,
    pub artists: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub site_info: Option<SiteInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub searched_hash: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "site", content = "site_info")]
pub enum SiteInfo {
    FurAffinity(FurAffinityFile),
    #[serde(rename = "e621")]
    E621(E621File),
    Twitter,
    Weasyl,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FurAffinityFile {
    pub file_id: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct E621File {
    pub sources: Option<Vec<String>>,
}

/// Search for multiple hashes at once, returning a hashmap of each searched
/// hash and the corresponding matches.
pub fn get_hashes(
    agent: &ureq::Agent,
    api_key: &str,
    hashes: &[i64],
) -> anyhow::Result<(HashMap<i64, Vec<File>>, i16, i64)> {
    let resp = agent
        .get("https://api-next.fuzzysearch.net/hashes")
        .set("X-Api-Key", api_key)
        .query(
            "hashes",
            &hashes
                .iter()
                .map(|hash| hash.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
        .query("distance", "3")
        .call()?;

    let next_rate_limit: i16 = resp
        .headers_names()
        .into_iter()
        .filter(|name| name.starts_with("x-rate-limit-remaining-"))
        .flat_map(|name| resp.header(&name))
        .flat_map(|remaining| remaining.parse())
        .min()
        .unwrap_or_default();
    debug!("found next rate limit: {next_rate_limit}");

    let rate_limit_reset: i64 = resp
        .header("x-rate-limit-reset")
        .and_then(|reset| reset.parse().ok())
        .unwrap_or_default();
    debug!("found rate limit reset: {rate_limit_reset}");

    let files: Vec<File> = resp.into_json()?;

    let mut items: HashMap<i64, Vec<File>> = HashMap::new();

    for item in files {
        let entry = items
            .entry(item.searched_hash.expect("Missing searched hash"))
            .or_default();
        entry.push(item);
    }

    Ok((items, next_rate_limit, rate_limit_reset))
}

/// Generate a URL for a given File.
pub fn url_for_file(item: File) -> String {
    let site_info = item.site_info.expect("Missing site info in database");

    match site_info {
        SiteInfo::FurAffinity(_) => {
            format!("https://www.furaffinity.net/view/{}/", item.site_id)
        }
        SiteInfo::E621(_) => {
            format!("https://e621.net/post/show/{}", item.site_id)
        }
        SiteInfo::Twitter => format!(
            "https://twitter.com/{}/status/{}",
            item.artists.unwrap()[0],
            item.site_id
        ),
        SiteInfo::Weasyl => {
            format!("https://www.weasyl.com/view/{}/", item.site_id)
        }
    }
}

/// Prepare the index by looking up each hash.
pub fn prepare_index(
    conn: &rusqlite::Connection,
    api_key: &str,
    lookup_count: usize,
) -> anyhow::Result<()> {
    let mut stmt = conn
        .prepare("SELECT id, hash FROM cache WHERE looked_up = FALSE LIMIT ?1")
        .expect("Unable to prepare query to lookup items needing resolution");

    let mut insert_stmt = conn
        .prepare("INSERT OR IGNORE INTO hashes (hash, data) VALUES (?1, ?2)")
        .expect("Unable to prepare query to insert hash info");
    let mut update_stmt = conn
        .prepare("UPDATE cache SET hash_lookup_id = ?1, looked_up = TRUE WHERE id = ?2")
        .expect("Unable to prepare query to update cache item");

    let pb = indicatif::ProgressBar::new(lookup_count as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}): {msg}"
            ).unwrap()
            .progress_chars("#>-")
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let agent = ureq::agent();

    let mut next_chunk_size = 10;

    loop {
        debug!("using chunk size: {next_chunk_size}");
        let rows: Vec<(i32, i64)> = stmt
            .query_map([next_chunk_size], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("Unable to lookup items needing resolution")
            .filter_map(|row| row.ok())
            .collect();

        if rows.is_empty() {
            debug!("rows was empty");
            break;
        }

        let items: Vec<_> = rows.iter().map(|row| row.1).collect();

        let (hashes, next_rate_limit, rate_limit_reset) = loop {
            match get_hashes(&agent, api_key, &items) {
                Ok(hashes) => break hashes,
                Err(err) => {
                    debug!("api error: {err}");
                    pb.set_message("Got API error, retrying in 30 seconds");
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    pb.set_message("");
                }
            }
        };
        debug!("next rate limit: {next_rate_limit}");

        for item in rows.iter() {
            if let Some(files) = hashes.get(&item.1) {
                let data = serde_json::to_string(&files).expect("Unable to serialize hash lookup");

                insert_stmt
                    .execute(rusqlite::params![item.1, &data])
                    .expect("Unable to insert hash lookup data");

                let hash_id = conn.last_insert_rowid();
                update_stmt
                    .execute(rusqlite::params![hash_id, item.0])
                    .expect("Unable to update cache with hash data ID");
            } else {
                update_stmt
                    .execute(rusqlite::params![rusqlite::types::Null, item.0])
                    .expect("Unable to set hash lookup to None");
            }
        }

        pb.inc(rows.len() as u64);

        if next_rate_limit == 0 {
            let secs = u64::try_from(rate_limit_reset).unwrap_or_default() + 1;
            pb.set_message(format!("Reached rate limit, waiting {secs} seconds"));
            std::thread::sleep(std::time::Duration::from_secs(secs));
            pb.set_message("");
            next_chunk_size = 10;
        } else {
            next_chunk_size = next_rate_limit.clamp(1, 10);
        }
    }

    pb.abandon();

    Ok(())
}
