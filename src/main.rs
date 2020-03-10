use clap::{value_t, App, Arg};
use futures::stream::StreamExt;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use tokio::prelude::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct File {
    pub id: i32,

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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FurAffinityFile {
    pub file_id: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct E621File {
    pub sources: Option<Vec<String>>,
}

#[derive(Debug)]
struct ImageInfo {
    id: i32,
    hash: [u8; 8],
    path: std::path::PathBuf,
}

async fn hash_image(id: i32, path: String) -> Option<ImageInfo> {
    trace!("Opening image: {}", path);

    let p = std::path::Path::new(&path).to_path_buf();

    tokio::spawn(async move {
        let mut f = match tokio::fs::File::open(&p).await {
            Ok(f) => f,
            Err(e) => {
                error!("Unable to open image {:?}: {}", p.to_str(), e);
                return None;
            }
        };

        let mut buf = match f.metadata().await {
            Ok(m) => Vec::with_capacity(m.len() as usize),
            Err(e) => {
                error!("Unable to find size of image: {:?}: {}", p.to_str(), e);
                return None;
            }
        };

        if let Err(e) = f.read_to_end(&mut buf).await {
            error!("Unable to read image: {:?}: {}", p.to_str(), e);
            return None;
        }

        let image = match image::load_from_memory(&buf) {
            Ok(image) => image,
            Err(e) => {
                warn!("Unable to decode image: {:?}: {}", p.to_str(), e);
                return None;
            }
        };

        let hasher = img_hash::HasherConfig::with_bytes_type::<[u8; 8]>()
            .hash_alg(img_hash::HashAlg::Gradient)
            .hash_size(8, 8)
            .preproc_dct()
            .to_hasher();

        let hash = hasher.hash_image(&image);
        let bytes = hash.as_bytes();

        let mut b: [u8; 8] = [0; 8];
        b.copy_from_slice(&bytes);

        debug!("Hashed {}", p.to_str().unwrap());

        Some(ImageInfo {
            hash: b,
            path: p,
            id,
        })
    })
    .await
    .ok()
    .flatten()
}

async fn get_hashes(api_key: &str, hashes: &[i64]) -> reqwest::Result<HashMap<i64, Vec<File>>> {
    let mut params = HashMap::new();
    params.insert(
        "hashes",
        hashes
            .iter()
            .map(|hash| hash.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    params.insert("distance", 3.to_string());

    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.fuzzysearch.net/hashes")
        .header("X-Api-Key", api_key.as_bytes())
        .query(&params)
        .send()
        .await?;

    let resp: Vec<File> = resp.json().await?;

    let mut items: HashMap<i64, Vec<File>> = HashMap::new();
    for item in resp {
        let entry = items
            .entry(item.searched_hash.expect("Missing searched hash"))
            .or_default();
        entry.push(item);
    }

    Ok(items)
}

#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn,fuzzysearch_cli=info");
    }

    pretty_env_logger::init();

    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("directory")
                .index(1)
                .takes_value(true)
                .required(true)
                .help("Folder to look for images in"),
        )
        .arg(
            Arg::with_name("output")
                .index(2)
                .takes_value(true)
                .required(false)
                .default_value("output.txt")
                .help("File where duplicates information is saved"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short("c")
                .long("concurrency")
                .takes_value(true)
                .required(false)
                .default_value("8")
                .help("Maximun number of images to hash at once"),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .takes_value(true)
                .required(true)
                .help("Your FuzzySearch API key"),
        )
        .arg(
            Arg::with_name("limit")
                .short("l")
                .long("limit")
                .takes_value(true)
                .required(false)
                .help("API limit per minute")
                .default_value("60"),
        )
        .arg(
            Arg::with_name("move-matched")
                .long("move-matched")
                .takes_value(true)
                .required(false)
                .help("Move matched items to directory"),
        )
        .arg(
            Arg::with_name("move-unmatched")
                .long("move-unmatched")
                .takes_value(true)
                .required(false)
                .help("Move unmatched items to directory"),
        )
        .get_matches();

    let dir = matches.value_of("directory").unwrap();
    let output = matches.value_of("output").unwrap();
    let buffer_size = value_t!(matches, "concurrency", usize).unwrap_or_else(|e| e.exit());
    let api_key = matches.value_of("key").unwrap();
    let api_limit = value_t!(matches, "limit", i32).unwrap_or_else(|e| e.exit());
    let move_matched = matches.value_of("move-matched").map(std::path::Path::new);
    let move_unmatched = matches.value_of("move-unmatched").map(std::path::Path::new);

    if let Some(move_matched) = move_matched {
        if !move_matched.exists() {
            error!("Move matched directory does not exist");
            std::process::exit(1);
        }
    }

    if let Some(move_unmatched) = move_unmatched {
        if !move_unmatched.exists() {
            error!("Move unmatched directory does not exist");
            std::process::exit(1);
        }
    }

    let project_dir = directories::ProjectDirs::from("net", "fuzzysearch", "fuzzysearch-cli")
        .expect("Unable to get working directory");
    let data_dir = project_dir.data_dir();
    std::fs::create_dir_all(&data_dir).expect("Unable to create working directory");

    let conn =
        rusqlite::Connection::open(data_dir.join("hashes.db")).expect("Unable to create database");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS hashes (
        id INTEGER PRIMARY KEY,
        hash INTEGER UNIQUE NOT NULL,
        data TEXT NOT NULL
    )",
        rusqlite::params![],
    )
    .expect("Unable to create hashes table");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache (
        id INTEGER PRIMARY KEY,
        path TEXT NOT NULL UNIQUE,
        hash INTEGER,
        hash_lookup_id INTEGER,
        looked_up BOOL NOT NULL DEFAULT FALSE,
        FOREIGN KEY (hash_lookup_id) REFERENCES hashes(id)
    )",
        rusqlite::params![],
    )
    .expect("Unable to create cache table");

    info!("Starting...");

    let mut stmt = conn
        .prepare("SELECT 1 FROM cache WHERE path = ?1")
        .expect("Unable to prepare cache lookup query");
    let mut insert_stmt = conn
        .prepare("INSERT INTO cache (path) VALUES (?1)")
        .expect("Unable to prepare cache insert query");
    for entry in walkdir::WalkDir::new(dir) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                error!("An error occurred: {}", e);
                return;
            }
        };

        trace!("Looking at {:?}", entry);

        let path = entry.path();

        let ext = match path.extension() {
            Some(ext) => ext.to_string_lossy().to_string().to_lowercase(),
            None => {
                trace!("File had no extension");
                continue;
            }
        };

        match ext.as_ref() {
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "bmp" => {
                trace!("Is relevant file");
            }
            _ => continue,
        }

        if stmt
            .exists(rusqlite::params![path.to_string_lossy()])
            .expect("Unable to search cache for path")
        {
            debug!("{:?} already hashed", path);
        } else {
            insert_stmt
                .execute(rusqlite::params![path.to_string_lossy()])
                .expect("Unable to insert item to cache");
        }
    }

    let mut stmt = conn
        .prepare("SELECT id, path FROM cache WHERE hash IS NULL")
        .expect("Unable to prepare cache lookup query");
    let needed_hashes: Vec<(i32, String)> = stmt
        .query_map(rusqlite::NO_PARAMS, |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("Unable to find items needing lookup")
        .filter_map(|row| row.ok())
        .collect();

    info!("Found {} files to evaluate", needed_hashes.len());

    let start = std::time::Instant::now();
    let len = needed_hashes.len();

    let pb = indicatif::ProgressBar::new(len as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] ({eta})")
            .progress_chars("#>-"),
    );

    futures::stream::iter(
        needed_hashes
            .into_iter()
            .map(|file| hash_image(file.0, file.1)),
    )
    .buffer_unordered(buffer_size)
    .filter_map(futures::future::ready)
    .for_each(|hash| {
        conn.execute(
            "UPDATE cache SET hash = ?1 WHERE id = ?2",
            rusqlite::params![i64::from_be_bytes(hash.hash), hash.id],
        )
        .expect("Unable to insert item into hash cache");
        pb.inc(1);
        futures::future::ready(())
    })
    .await;

    pb.finish_with_message(&format!(
        "Hashed {} items in {} seconds",
        len,
        start.elapsed().as_secs()
    ));

    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM cache WHERE looked_up = FALSE")
        .expect("Unable to prepare count query");
    let count: i32 = stmt
        .query_row(rusqlite::NO_PARAMS, |row| row.get(0))
        .expect("Unable to get count");

    let mut stmt = conn
        .prepare("SELECT id, hash FROM cache WHERE looked_up = FALSE LIMIT ?1")
        .expect("Unable to prepare query to lookup items needing resolution");

    let mut insert_stmt = conn
        .prepare("INSERT OR IGNORE INTO hashes (hash, data) VALUES (?1, ?2)")
        .expect("Unable to prepare query to insert hash info");
    let mut update_stmt = conn
        .prepare("UPDATE cache SET hash_lookup_id = ?1, looked_up = TRUE WHERE id = ?2")
        .expect("Unable to prepare query to update cache item");

    info!("Starting to look up hashes");

    let pb = indicatif::ProgressBar::new(count as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] ({eta})")
            .progress_chars("#>-"),
    );

    loop {
        let rows: Vec<(i32, i64)> = stmt
            .query_map(rusqlite::params![&api_limit], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
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
                match get_hashes(api_key, &items).await {
                    Ok(hashes) => break hashes,
                    Err(_err) => {
                        warn!("Got API error, retrying in 30 seconds");
                        tokio::time::delay_for(std::time::Duration::from_secs(30)).await;
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

        if rows.len() < 30 {
            break;
        }

        let delay: i32 = 61 - (start.elapsed().as_secs() as i32);
        if delay > 0 {
            tokio::time::delay_for(std::time::Duration::from_secs(delay as u64)).await;
        }
    }

    pb.finish_with_message("Completed hash lookup");

    let mut stmt = conn
        .prepare("SELECT data FROM hashes")
        .expect("Unable to select hash data");

    let sources_data: Vec<rusqlite::Result<String>> = stmt
        .query_map(rusqlite::NO_PARAMS, |row| row.get(0))
        .expect("Unable to find items needing lookup")
        .collect();

    let sources: Vec<Vec<String>> = sources_data
        .into_iter()
        .map(|item| {
            let s = item.expect("Row was bad");
            let data: Vec<File> =
                serde_json::from_str(&s).expect("Database contained malformed data");

            data.into_iter()
                .map(|item| {
                    let site_info = item.site_info.expect("Missing site info in database");

                    match site_info {
                        SiteInfo::FurAffinity(_) => {
                            format!("https://www.furaffinity.net/view/{}/", item.site_id)
                        }
                        SiteInfo::E621(_) => format!("https://e621.net/post/show/{}", item.site_id),
                        SiteInfo::Twitter => format!(
                            "https://twitter.com/{}/status/{}",
                            item.artists.unwrap().get(0).unwrap(),
                            item.site_id
                        ),
                    }
                })
                .collect()
        })
        .collect();

    let mut sources: Vec<String> = sources.into_iter().flatten().collect();
    sources.sort();
    sources.dedup();

    let mut f = tokio::fs::File::create(output)
        .await
        .expect("Unable to create output file");
    for source in sources {
        f.write_all(format!("{}\n", source).as_bytes())
            .await
            .expect("Unable to write source");
    }

    if let Some(move_matched) = move_matched {
        info!("Moving matched items to {}", move_matched.display());
        remove_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NOT NULL",
            move_matched,
        );
    }

    if let Some(move_unmatched) = move_unmatched {
        info!("Moving unmatched items to {}", move_unmatched.display());
        remove_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NULL",
            move_unmatched,
        );
    }

    info!("Done!");
}

fn remove_items(conn: &rusqlite::Connection, query: &str, move_to: &std::path::Path) {
    let mut stmt = conn.prepare(query).expect("Unable to prepare lookup");
    let mut remove = conn
        .prepare("DELETE FROM cache WHERE id = ?")
        .expect("Unable to prepare delete");
    let rows: Vec<rusqlite::Result<(i32, String)>> = stmt
        .query_map(rusqlite::NO_PARAMS, |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("Unable to query")
        .collect();

    for row in rows {
        let (id, path) = row.expect("Missing data from row");
        let path = std::path::Path::new(&path);
        let filename = path.file_name().expect("File missing name");

        std::fs::rename(path, move_to.join(filename)).expect("Unable to rename file");
        remove
            .execute(rusqlite::params![id])
            .expect("Unable to remove item from cache");
    }
}
