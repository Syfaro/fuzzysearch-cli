use std::collections::HashMap;
use std::path::Path;

use clap::Parser;
use futures::stream::StreamExt;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        b.copy_from_slice(bytes);

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

#[derive(Parser)]
#[clap(name = env!("CARGO_PKG_NAME"), version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
struct Opts {
    /// Maximun number of images to hash at once
    #[clap(short, long, default_value = "8")]
    concurrency: usize,
    /// FuzzySearch API key
    #[clap(long, required_unless_present = "database-path")]
    api_key: Option<String>,
    /// FuzzySearch database dump path
    #[clap(long)]
    database_path: Option<String>,
    /// API limit per minute
    #[clap(short, long, default_value = "60")]
    limit: i32,
    /// Move matched items to directory
    #[clap(long)]
    move_matched: Option<String>,
    /// Move matched items to directory
    #[clap(long)]
    move_unmatched: Option<String>,
    /// Path to folder containing images
    directory: String,
    /// How to output source information
    #[clap(arg_enum)]
    action: Action,
    /// Where to output source information
    #[clap(default_value = "sources.txt")]
    output: String,
}

#[derive(Debug, clap::ArgEnum, Clone)]
enum Action {
    AllSources,
    PerFile,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Site {
    FurAffinity,
    Weasyl,
    E621,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct Item {
    site: Site,
    id: i64,
    artists: String,
    hash: Option<i64>,
    posted_at: Option<String>,
    updated_at: Option<String>,
    #[serde(with = "b64_vec")]
    sha256: Option<Vec<u8>>,
    deleted: bool,
}

mod b64_vec {
    use serde::Deserialize;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = <Option<String>>::deserialize(deserializer)?
            .map(base64::decode)
            .transpose()
            .map_err(serde::de::Error::custom)?;

        Ok(val)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Node([u8; 8]);

struct Hamming;

impl bk_tree::Metric<Node> for Hamming {
    fn distance(&self, a: &Node, b: &Node) -> u32 {
        hamming::distance_fast(&a.0, &b.0).unwrap() as u32
    }

    fn threshold_distance(&self, a: &Node, b: &Node, _threshold: u32) -> Option<u32> {
        Some(self.distance(a, b))
    }
}

impl From<i64> for Node {
    fn from(num: i64) -> Self {
        Self(num.to_be_bytes())
    }
}

impl From<Node> for i64 {
    fn from(node: Node) -> Self {
        i64::from_be_bytes(node.0)
    }
}

#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn,fuzzysearch_cli=info");
    }

    pretty_env_logger::init();

    let opts = Opts::parse();

    if let Some(move_matched) = &opts.move_matched {
        let path = Path::new(move_matched);
        if !path.exists() {
            error!("Move matched directory does not exist");
            std::process::exit(1);
        }
    }

    if let Some(move_unmatched) = &opts.move_unmatched {
        let path = Path::new(move_unmatched);
        if !path.exists() {
            error!("Move unmatched directory does not exist");
            std::process::exit(1);
        }
    }

    info!("Creating working directories");

    let project_dir = directories::ProjectDirs::from("net", "fuzzysearch", "fuzzysearch-cli")
        .expect("Unable to get working directory");
    let data_dir = project_dir.data_dir();
    std::fs::create_dir_all(&data_dir).expect("Unable to create working directory");

    let mut conn =
        rusqlite::Connection::open(data_dir.join("hashes.db")).expect("Unable to create database");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS hashes (
        id INTEGER PRIMARY KEY,
        hash INTEGER UNIQUE NOT NULL,
        data TEXT NOT NULL
    )",
        [],
    )
    .expect("Unable to create hashes table");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS local_hashes (
        id INTEGER PRIMARY KEY,
        hash INTEGER NOT NULL,
        site TEXT NOT NULL,
        site_id INTEGER NOT NULL,
        CONSTRAINT local_site UNIQUE(site, site_id)
    )",
        [],
    )
    .expect("Unable to create local_hashes table");
    conn.execute(
        "CREATE INDEX IF NOT EXISTS local_hash_idx ON local_hashes (hash)",
        [],
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache (
        id INTEGER PRIMARY KEY,
        path TEXT NOT NULL UNIQUE,
        hash INTEGER,
        hash_lookup_id INTEGER,
        looked_up BOOL NOT NULL DEFAULT FALSE,
        FOREIGN KEY (hash_lookup_id) REFERENCES hashes(id)
    )",
        [],
    )
    .expect("Unable to create cache table");

    info!("Starting to process files");

    let mut stmt = conn
        .prepare("SELECT 1 FROM cache WHERE path = ?1")
        .expect("Unable to prepare cache lookup query");
    let mut insert_stmt = conn
        .prepare("INSERT INTO cache (path) VALUES (?1)")
        .expect("Unable to prepare cache insert query");

    for entry in walkdir::WalkDir::new(&opts.directory) {
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

        let path = path.to_string_lossy();

        if stmt
            .exists(rusqlite::params![path])
            .expect("Unable to search cache for path")
        {
            debug!("{:?} already hashed", path);
        } else {
            insert_stmt
                .execute(rusqlite::params![path])
                .expect("Unable to insert item to cache");
        }
    }

    drop(stmt);
    drop(insert_stmt);

    let mut stmt = conn
        .prepare("SELECT id, path FROM cache WHERE hash IS NULL")
        .expect("Unable to prepare cache lookup query");
    let needed_hashes: Vec<(i32, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("Unable to find items needing lookup")
        .filter_map(|row| row.ok())
        .collect();
    drop(stmt);

    info!("Found {} files to evaluate", needed_hashes.len());

    let start = std::time::Instant::now();
    let len = needed_hashes.len();

    let pb = indicatif::ProgressBar::new(len as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .progress_chars("#>-"),
    );

    futures::stream::iter(
        needed_hashes
            .into_iter()
            .map(|file| hash_image(file.0, file.1)),
    )
    .buffer_unordered(opts.concurrency)
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

    pb.finish_with_message(format!(
        "Hashed {} items in {} seconds",
        len,
        start.elapsed().as_secs()
    ));

    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM cache WHERE looked_up = FALSE")
        .expect("Unable to prepare count query");
    let count: i32 = stmt
        .query_row([], |row| row.get(0))
        .expect("Unable to get count");
    drop(stmt);

    let tree = if let Some(database_path) = opts.database_path.as_ref() {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {pos} completed, {per_sec} {msg}"),
        );
        pb.set_message("Indexing database");

        let path = Path::new(&database_path);

        let file = tokio::fs::File::open(path)
            .await
            .expect("could not open database file");
        let mut reader = csv_async::AsyncDeserializer::from_reader(file);
        let mut records = reader.deserialize::<Item>();

        let tx = conn.transaction().unwrap();

        let mut stmt = tx
            .prepare("INSERT OR IGNORE INTO local_hashes (hash, site, site_id) VALUES (?1, ?2, ?3)")
            .unwrap();

        let mut tree = bk_tree::BKTree::new(Hamming);

        while let Some(Ok(row)) = records.next().await {
            pb.inc(1);

            if let Some(hash) = row.hash {
                stmt.execute(rusqlite::params![
                    hash,
                    serde_json::to_string(&row.site).unwrap(),
                    row.id
                ])
                .expect("could not insert local hash");

                let hash: Node = hash.into();
                if tree.find_exact(&hash).is_none() {
                    tree.add(hash);
                }
            }
        }

        drop(stmt);
        tx.commit().unwrap();

        pb.finish_at_current_pos();

        Some(tree)
    } else if let Some(api_key) = opts.api_key {
        let mut stmt = conn
            .prepare("SELECT id, hash FROM cache WHERE looked_up = FALSE LIMIT ?1")
            .expect("Unable to prepare query to lookup items needing resolution");

        let mut insert_stmt = conn
            .prepare("INSERT OR IGNORE INTO hashes (hash, data) VALUES (?1, ?2)")
            .expect("Unable to prepare query to insert hash info");
        let mut update_stmt = conn
            .prepare("UPDATE cache SET hash_lookup_id = ?1, looked_up = TRUE WHERE id = ?2")
            .expect("Unable to prepare query to update cache item");

        let pb = indicatif::ProgressBar::new(count as u64);
        pb.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}): {msg}"
                )
                .progress_chars("#>-")
        );
        pb.enable_steady_tick(100);
        pb.set_message("Looking up hashes");

        loop {
            let rows: Vec<(i32, i64)> = stmt
                .query_map(rusqlite::params![&opts.limit], |row| {
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
                    match get_hashes(&api_key, &items).await {
                        Ok(hashes) => break hashes,
                        Err(err) => {
                            warn!("Got API error, retrying in 30 seconds: {}", err);
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
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
                tokio::time::sleep(std::time::Duration::from_secs(delay as u64)).await;
            }
        }

        pb.finish_with_message("Completed hash lookup");

        None
    } else {
        None
    };

    let mut f = tokio::fs::File::create(opts.output)
        .await
        .expect("Unable to create output file");

    let mut stmt = conn
        .prepare("SELECT cache.hash FROM cache WHERE cache.path = ?1")
        .unwrap();

    info!("Completed index, evaluating files");

    let files = walkdir::WalkDir::new(&opts.directory)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path().to_string_lossy();

            stmt.query_map(&[&path], |row| row.get::<_, i64>(0))
                .expect("could not query rows")
                .find_map(|row| row.ok())
                .map(|hash| (path.to_string(), hash))
        });

    let mut sources: HashMap<String, Vec<String>> = HashMap::new();

    let mut stmt = conn
        .prepare("SELECT data FROM hashes WHERE hash = ?1")
        .expect("Unable to select hash data");
    let mut tree_stmt = conn
        .prepare("SELECT site, site_id FROM local_hashes WHERE hash = ?1")
        .unwrap();

    info!("Calculating image sources");

    for (path, hash) in files {
        let entry = sources.entry(path).or_default();

        let matches: Vec<String> = if let Some(tree) = &tree {
            let mut matches = Vec::new();

            for (_distance, matching_hash) in tree.find(&hash.into(), 3).into_iter() {
                tree_stmt
                    .query_map([i64::from(*matching_hash)], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .unwrap()
                    .into_iter()
                    .filter_map(|row| row.ok())
                    .for_each(|(site, site_id)| {
                        let site: Site = serde_json::from_str(&site).unwrap();
                        matches.push(url_for_tuple(site, site_id));
                    });
            }

            matches
        } else {
            let mut matches = Vec::new();

            for data in stmt
                .query_map([hash], |row| row.get::<_, String>(0))
                .unwrap()
            {
                let data = data.unwrap();
                let files = serde_json::from_str::<Vec<File>>(&data).unwrap_or_default();
                matches.extend(files.into_iter().map(url_for_file));
            }

            matches
        };

        *entry = matches;
    }

    info!("Sources calculated, writing output");

    match opts.action {
        Action::AllSources => {
            let mut sources: Vec<String> = sources
                .into_iter()
                .map(|(_path, sources)| sources)
                .flatten()
                .collect();
            sources.sort();
            sources.dedup();

            for source in sources {
                f.write_all(format!("{}\n", source).as_bytes())
                    .await
                    .expect("Unable to write source");
            }
        }
        Action::PerFile => {
            let mut csv = csv_async::AsyncWriter::from_writer(f);

            for (path, sources) in sources {
                csv.write_record(&[path, sources.join(" ")])
                    .await
                    .expect("could not write csv record");
            }
        }
    }

    if let Some(move_matched) = opts.move_matched {
        let path = Path::new(&move_matched);
        info!("Moving matched items to {}", path.display());
        remove_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NOT NULL",
            path,
        );
    }

    if let Some(move_unmatched) = opts.move_unmatched {
        let path = Path::new(&move_unmatched);
        info!("Moving unmatched items to {}", path.display());
        remove_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NULL",
            path,
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
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
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

fn url_for_file(item: File) -> String {
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

fn url_for_tuple(site: Site, site_id: i64) -> String {
    match site {
        Site::FurAffinity => format!("https://www.furaffinity.net/view/{}/", site_id),
        Site::E621 => format!("https://e621.net/post/show/{}", site_id),
        Site::Weasyl => format!("https://www.weasyl.com/view/{}", site_id),
    }
}
