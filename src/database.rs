use std::path::Path;

use futures::StreamExt;
use serde::{Deserialize, Serialize};

/// A node in the BK tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node([u8; 8]);

/// A hamming distance metric for a BK tree.
pub struct Hamming;

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

/// A site that can be contained in a database dump.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Site {
    FurAffinity,
    Weasyl,
    E621,
}

/// A row from FuzzySearch's database dump.
#[derive(Clone, Debug, Deserialize)]
pub struct Item {
    /// The site this item was collected from.
    pub site: Site,
    /// The ID of the submission.
    pub id: i64,
    /// Artists of this submission, typically only one.
    pub artists: String,
    /// The hash for the image, if one exists.
    pub hash: Option<i64>,
    /// When the submission was posted at.
    pub posted_at: Option<String>,
    /// When the submission was last retrieved.
    pub updated_at: Option<String>,
    /// The SHA256 of the submission image file. This may not always exist.
    #[serde(with = "b64_vec")]
    pub sha256: Option<Vec<u8>>,
    /// If the submission was deleted on last check.
    pub deleted: bool,
}

/// A custom deserializer for bytes encoded as base64.
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

/// Generate a URL for a given site and ID on that site.
pub fn url_for(site: Site, site_id: i64) -> String {
    match site {
        Site::FurAffinity => format!("https://www.furaffinity.net/view/{}/", site_id),
        Site::E621 => format!("https://e621.net/post/show/{}", site_id),
        Site::Weasyl => format!("https://www.weasyl.com/view/{}", site_id),
    }
}

/// Prepare the database index.
///
/// This imports all items from the dump into the SQLite database and creates
/// a BK tree from all unique hashes.
pub async fn prepare_index(
    conn: &mut rusqlite::Connection,
    database_path: &str,
    only_cached: bool,
) -> anyhow::Result<bk_tree::BKTree<Node, Hamming>> {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {pos} completed, {per_sec}"),
    );

    let mut tree = bk_tree::BKTree::new(Hamming);

    if only_cached {
        let mut stmt = conn.prepare("SELECT hash FROM local_hashes")?;
        for hash in stmt.query_map([], |row| row.get::<_, i64>(0))? {
            pb.inc(1);

            let hash: Node = hash?.into();
            if tree.find_exact(&hash).is_none() {
                tree.add(hash);
            }
        }

        pb.finish_at_current_pos();
        return Ok(tree);
    }

    let path = Path::new(&database_path);

    let file = tokio::fs::File::open(path).await?;
    let mut reader = csv_async::AsyncDeserializer::from_reader(file);
    let mut records = reader.deserialize::<Item>();

    let tx = conn.transaction()?;
    let mut stmt =
        tx.prepare("INSERT OR IGNORE INTO local_hashes (hash, site, site_id) VALUES (?1, ?2, ?3)")?;

    while let Some(Ok(row)) = records.next().await {
        pb.inc(1);

        if let Some(hash) = row.hash {
            stmt.execute(rusqlite::params![
                hash,
                serde_json::to_string(&row.site).unwrap(),
                row.id
            ])?;

            let hash: Node = hash.into();
            if tree.find_exact(&hash).is_none() {
                tree.add(hash);
            }
        }
    }

    drop(stmt);
    tx.commit().unwrap();
    pb.finish_at_current_pos();

    Ok(tree)
}