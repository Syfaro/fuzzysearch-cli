use std::collections::HashMap;

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
) -> anyhow::Result<HashMap<i64, Vec<File>>> {
    let resp: Vec<File> = agent
        .get("https://api.fuzzysearch.net/hashes")
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
        .call()?
        .into_json()?;

    let mut items: HashMap<i64, Vec<File>> = HashMap::new();

    for item in resp {
        let entry = items
            .entry(item.searched_hash.expect("Missing searched hash"))
            .or_default();
        entry.push(item);
    }

    Ok(items)
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
    rate_limit: usize,
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
            )
            .progress_chars("#>-")
    );
    pb.enable_steady_tick(100);

    let agent = ureq::agent();

    loop {
        let rows: Vec<(i32, i64)> = stmt
            .query_map([rate_limit], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("Unable to lookup items needing resolution")
            .filter_map(|row| row.ok())
            .collect();

        if rows.is_empty() {
            break;
        }

        let start = std::time::Instant::now();

        let mut lookup = std::collections::HashMap::new();
        for row in rows.iter() {
            lookup.insert(row.1, row.0);
        }

        for chunk in rows.chunks(10) {
            let items: Vec<_> = chunk.iter().map(|chunk| chunk.1).collect();

            let hashes = loop {
                match get_hashes(&agent, api_key, &items) {
                    Ok(hashes) => break hashes,
                    Err(_err) => {
                        pb.set_message("Got API error, retrying in 30 seconds");
                        std::thread::sleep(std::time::Duration::from_secs(30));
                        pb.set_message("");
                    }
                }
            };

            for item in chunk.iter() {
                if let Some(files) = hashes.get(&item.1) {
                    let data =
                        serde_json::to_string(&files).expect("Unable to serialize hash lookup");

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

            pb.inc(chunk.len() as u64);
        }

        let delay = 61 - start.elapsed().as_secs();
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }
    }

    pb.finish_at_current_pos();

    Ok(())
}
