use std::io::Write;
use std::path::Path;
use std::{collections::HashMap, convert::TryInto};

use clap::Parser;
use log::{debug, error, info, trace, warn};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rayon::iter::{ParallelBridge, ParallelIterator};

mod database;
mod fuzzysearch;

#[derive(Parser)]
#[clap(name = env!("CARGO_PKG_NAME"), version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
struct Opts {
    /// FuzzySearch API key
    #[clap(long, required_unless_present = "database-path")]
    api_key: Option<String>,
    /// FuzzySearch database dump path
    #[clap(long)]
    database_path: Option<String>,
    /// Only use cached database values instead of re-reading dump
    #[clap(long, requires = "database-path")]
    cached_database: bool,
    /// API limit per minute
    #[clap(short, long, default_value = "60")]
    limit: usize,
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

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn,fuzzysearch_cli=info");
    }

    pretty_env_logger::init();

    let opts = Opts::parse();

    if !verify_directory(&opts.move_matched) {
        error!("Move matched directory does not exist");
        std::process::exit(1);
    }

    if !verify_directory(&opts.move_unmatched) {
        error!("Move unmatched directory does not exist");
        std::process::exit(1);
    }

    if opts.cached_database {
        warn!("Only using already cached values from database dump");
    }

    info!("Creating working database");
    let pool = initialize_database().expect("Could not create database");
    let conn = pool.get().unwrap();

    info!("Collecting information about files to scan");

    let _file_count =
        collect_local_images(&conn, &opts.directory).expect("Could not collect local files");

    let needed_hashes =
        get_unhashed_images(&conn).expect("Could not collect images needing hashing");

    info!("Found {} files needing hashing", needed_hashes.len());

    hash_images(&pool, needed_hashes).expect("Could not hash images");

    let lookup_count = images_needing_lookup(&conn).expect("Could not count items needing lookup");

    let tree = if let Some(database_path) = opts.database_path.as_ref() {
        info!("Creating index");

        let tree = database::prepare_index(&pool, database_path, opts.cached_database)
            .expect("Could not create database index");

        Some(tree)
    } else if let Some(api_key) = opts.api_key {
        info!("Performing lookups");

        fuzzysearch::prepare_index(&pool, &api_key, opts.limit, lookup_count)
            .expect("Could not perform lookup");

        None
    } else {
        unreachable!("either --api-key or --database-path must be set");
    };

    info!("Calculating image sources");

    let mut stmt = conn
        .prepare("SELECT cache.hash FROM cache WHERE cache.path = ?1")
        .unwrap();

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

    let mut stmt = conn
        .prepare("SELECT data FROM hashes WHERE hash = ?1")
        .expect("Unable to select hash data");
    let mut tree_stmt = conn
        .prepare("SELECT site, site_id FROM local_hashes WHERE hash = ?1")
        .unwrap();

    let mut sources: HashMap<String, Vec<String>> = HashMap::new();

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
                        let site: database::Site = serde_json::from_str(&site).unwrap();
                        matches.push(database::url_for(site, site_id));
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
                let files =
                    serde_json::from_str::<Vec<fuzzysearch::File>>(&data).unwrap_or_default();
                matches.extend(files.into_iter().map(fuzzysearch::url_for_file));
            }

            matches
        };

        *entry = matches;
    }

    info!("Sources calculated, writing output");

    let mut f = std::fs::File::create(opts.output).expect("Unable to create output file");

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
                    .expect("Unable to write source");
            }
        }
        Action::PerFile => {
            let mut csv = csv::Writer::from_writer(f);

            for (path, sources) in sources {
                csv.write_record(&[path, sources.join(" ")])
                    .expect("could not write csv record");
            }
        }
    }

    if let Some(move_matched) = opts.move_matched {
        let path = Path::new(&move_matched);
        info!("Moving matched items to {}", path.display());
        move_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NOT NULL",
            path,
        );
    }

    if let Some(move_unmatched) = opts.move_unmatched {
        let path = Path::new(&move_unmatched);
        info!("Moving unmatched items to {}", path.display());
        move_items(
            &conn,
            "SELECT id, path FROM cache WHERE looked_up = 1 AND hash_lookup_id IS NULL",
            path,
        );
    }

    info!("Done!");
}

/// A collection of information about an image on disk.
#[derive(Debug)]
struct ImageInfo {
    /// An arbitrary ID assigned to this image's path.
    id: i32,
    /// The hash of the image.
    hash: [u8; 8],
    /// The image file's path.
    path: std::path::PathBuf,
}

/// Attempt to hash an image.
///
/// Work is performed on tokio's blocking threads.
fn hash_image(id: i32, path: String) -> Option<ImageInfo> {
    trace!("Opening image: {}", path);

    let path = Path::new(&path);

    let image = image::open(path).ok()?;

    let hasher = img_hash::HasherConfig::with_bytes_type::<[u8; 8]>()
        .hash_alg(img_hash::HashAlg::Gradient)
        .hash_size(8, 8)
        .preproc_dct()
        .to_hasher();

    let hash = hasher.hash_image(&image);
    let bytes = hash.as_bytes();

    let hash: [u8; 8] = bytes.try_into().ok()?;

    debug!("Hashed {}", path.display());

    Some(ImageInfo {
        id,
        hash,
        path: path.to_path_buf(),
    })
}

/// Move items from a query to a new path and remove from cache.
fn move_items(conn: &rusqlite::Connection, query: &str, move_to: &Path) {
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
        let path = Path::new(&path);
        let filename = path.file_name().expect("File missing name");

        std::fs::rename(path, move_to.join(filename)).expect("Unable to rename file");
        remove
            .execute(rusqlite::params![id])
            .expect("Unable to remove item from cache");
    }
}

/// Verify a directory exists if it was provided.
fn verify_directory(dir: &Option<String>) -> bool {
    let dir = match dir {
        Some(dir) => dir,
        None => return true,
    };

    let path = Path::new(dir);
    path.exists()
}

/// Create storage directory and database.
fn initialize_database() -> anyhow::Result<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>> {
    let project_dir = directories::ProjectDirs::from("net", "fuzzysearch", "fuzzysearch-cli")
        .expect("System did not provide appropriate directories");
    let data_dir = project_dir.data_dir();
    std::fs::create_dir_all(&data_dir)?;

    let manager = SqliteConnectionManager::file(data_dir.join("hashes.db"));
    let pool = r2d2::Pool::new(manager)?;

    let conn = pool.get()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY,
            hash INTEGER UNIQUE NOT NULL,
            data TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS local_hashes (
            id INTEGER PRIMARY KEY,
            hash INTEGER NOT NULL,
            site TEXT NOT NULL,
            site_id INTEGER NOT NULL,
            CONSTRAINT local_site UNIQUE(site, site_id)
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS local_hash_idx ON local_hashes (hash)",
        [],
    )?;
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
    )?;

    Ok(pool)
}

/// Collect all local images and paths and store in database.
fn collect_local_images(conn: &rusqlite::Connection, dir: &str) -> anyhow::Result<usize> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM cache WHERE path = ?1")
        .expect("Unable to prepare cache lookup query");
    let mut insert_stmt = conn
        .prepare("INSERT INTO cache (path) VALUES (?1)")
        .expect("Unable to prepare cache insert query");

    let mut files = 0;

    for entry in walkdir::WalkDir::new(&dir) {
        let entry = entry?;

        trace!("Looking at {:?}", entry);

        let path = entry.path();

        let ext = match path.extension().map(|ext| ext.to_ascii_lowercase()) {
            Some(ext) => ext.to_string_lossy().to_string(),
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
        files += 1;

        if stmt.exists([&path])? {
            debug!("{:?} already hashed", path);
        } else {
            insert_stmt.execute([path])?;
        }
    }

    Ok(files)
}

/// Get every image still needing to be hashed.
fn get_unhashed_images(conn: &rusqlite::Connection) -> anyhow::Result<Vec<(i32, String)>> {
    let mut stmt = conn.prepare("SELECT id, path FROM cache WHERE hash IS NULL")?;
    let needed_hashes: Vec<(i32, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|row| row.ok())
        .collect();

    Ok(needed_hashes)
}

/// Hash many images at once, saving the result to the database.
fn hash_images(
    pool: &Pool<SqliteConnectionManager>,
    images: Vec<(i32, String)>,
) -> anyhow::Result<()> {
    let pb = indicatif::ProgressBar::new(images.len() as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .progress_chars("#>-"),
    );

    images
        .into_iter()
        .par_bridge()
        .filter_map(|file| hash_image(file.0, file.1))
        .for_each(|hash| {
            let conn = pool.get().unwrap();

            conn.execute(
                "UPDATE cache SET hash = ?1 WHERE id = ?2",
                rusqlite::params![i64::from_be_bytes(hash.hash), hash.id],
            )
            .expect("Unable to insert item into hash cache");

            pb.inc(1);
        });

    pb.finish_at_current_pos();

    Ok(())
}

/// Get count of images needing to be looked up.
fn images_needing_lookup(conn: &rusqlite::Connection) -> anyhow::Result<usize> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM cache WHERE looked_up = FALSE")?;
    let count: usize = stmt.query_row([], |row| row.get(0))?;

    Ok(count)
}
