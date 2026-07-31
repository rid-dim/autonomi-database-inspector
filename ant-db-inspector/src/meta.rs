//! Raw LMDB meta-page parser.
//!
//! LMDB keeps two meta pages at the start of `data.mdb` (pages 0 and 1) and
//! alternates between them on each commit; the one with the higher
//! transaction ID is the live root. Each meta page embeds the B-tree records
//! of the two internal databases: the freelist DB (`FREE_DBI`) and the main
//! DB (`MAIN_DBI`). Parsing them directly surfaces data that the regular
//! LMDB API does not expose: both meta generations, the on-disk map size,
//! environment flags persisted in the file, and the freelist B-tree shape.
//!
//! Layout (LMDB 0.9.x, 64-bit): a 16-byte page header followed by `MDB_meta`:
//!
//! ```text
//! offset  size  field
//! 0x00    4     mm_magic        (0xBEEFC0DE)
//! 0x04    4     mm_version      (MDB_DATA_VERSION, 1)
//! 0x08    8     mm_address      (fixed-map address, normally 0)
//! 0x10    8     mm_mapsize
//! 0x18    48    mm_dbs[0]       (freelist DB; md_pad holds the page size,
//!                                md_flags holds persistent env flags)
//! 0x48    48    mm_dbs[1]       (main DB)
//! 0x78    8     mm_last_pg
//! 0x80    8     mm_txnid
//! ```
//!
//! `MDB_db` record layout (48 bytes):
//!
//! ```text
//! offset  size  field
//! 0x00    4     md_pad           (page size in mm_dbs[0], else padding)
//! 0x04    2     md_flags
//! 0x06    2     md_depth
//! 0x08    8     md_branch_pages
//! 0x10    8     md_leaf_pages
//! 0x18    8     md_overflow_pages
//! 0x20    8     md_entries
//! 0x28    8     md_root          (P_INVALID = u64::MAX when empty)
//! ```

use serde::Serialize;
use std::path::Path;

/// LMDB magic number (`mm_magic`).
const MDB_MAGIC: u32 = 0xBE_EF_C0_DE;

/// Size of the page header preceding the meta struct.
const PAGE_HEADER_SIZE: usize = 16;

/// Size of one serialized `MDB_db` record.
const MDB_DB_SIZE: usize = 48;

/// `P_INVALID`: page-number value marking an empty B-tree root.
const P_INVALID: u64 = u64::MAX;

/// One of the two internal database records embedded in a meta page.
#[derive(Serialize, Clone, Copy)]
pub struct DbRecord {
    pub flags: u16,
    pub depth: u16,
    pub branch_pages: u64,
    pub leaf_pages: u64,
    pub overflow_pages: u64,
    pub entries: u64,
    /// Root page number; `None` when the B-tree is empty (`P_INVALID`).
    pub root_page: Option<u64>,
}

/// One parsed meta page.
#[derive(Serialize, Clone, Copy)]
pub struct MetaPage {
    pub magic_ok: bool,
    pub format_version: u32,
    pub map_size_on_disk: u64,
    pub last_page: u64,
    pub txn_id: u64,
    pub freelist_db: DbRecord,
    pub main_db: DbRecord,
}

/// Both meta pages plus derived fields.
#[derive(Serialize)]
pub struct MetaReport {
    /// Page size recorded in the file (`mm_dbs[0].md_pad`).
    pub page_size: u32,
    /// Persistent environment flags recorded in the file (`mm_dbs[0].md_flags`).
    pub env_flags: u16,
    /// Index (0 or 1) of the meta page with the higher transaction ID.
    pub active_meta: usize,
    pub meta_pages: [MetaPage; 2],
}

impl MetaReport {
    /// The live meta page (higher transaction ID).
    pub fn active(&self) -> &MetaPage {
        &self.meta_pages[self.active_meta]
    }
}

fn u16_at(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().expect("checked length"))
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().expect("checked length"))
}

fn u64_at(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().expect("checked length"))
}

fn parse_db_record(buf: &[u8]) -> DbRecord {
    let root = u64_at(buf, 0x28);
    DbRecord {
        flags: u16_at(buf, 0x04),
        depth: u16_at(buf, 0x06),
        branch_pages: u64_at(buf, 0x08),
        leaf_pages: u64_at(buf, 0x10),
        overflow_pages: u64_at(buf, 0x18),
        entries: u64_at(buf, 0x20),
        root_page: (root != P_INVALID).then_some(root),
    }
}

/// Parse one meta page starting at `page` (page header included).
fn parse_meta_page(page: &[u8]) -> Option<MetaPage> {
    let meta = page.get(PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + 0x88)?;
    Some(MetaPage {
        magic_ok: u32_at(meta, 0x00) == MDB_MAGIC,
        format_version: u32_at(meta, 0x04),
        map_size_on_disk: u64_at(meta, 0x10),
        freelist_db: parse_db_record(&meta[0x18..0x18 + MDB_DB_SIZE]),
        main_db: parse_db_record(&meta[0x48..0x48 + MDB_DB_SIZE]),
        last_page: u64_at(meta, 0x78),
        txn_id: u64_at(meta, 0x80),
    })
}

/// Read and parse both meta pages of an LMDB data file.
pub fn parse_meta(data_file: &Path) -> Result<MetaReport, String> {
    // 64 KiB covers both meta pages for every legal LMDB page size
    // (512 B .. 64 KiB); the file may be shorter, so read what is there.
    let mut buf = vec![0u8; 2 * 65536];
    let n = {
        use std::io::Read;
        let mut f = std::fs::File::open(data_file)
            .map_err(|e| format!("cannot open {}: {e}", data_file.display()))?;
        let mut total = 0;
        loop {
            match f.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(k) => total += k,
                Err(e) => return Err(format!("cannot read {}: {e}", data_file.display())),
            }
        }
        total
    };
    buf.truncate(n);

    let meta0 = parse_meta_page(&buf).ok_or("file too small for an LMDB meta page")?;
    if !meta0.magic_ok {
        return Err(format!(
            "not an LMDB data file: bad magic in {}",
            data_file.display()
        ));
    }

    // The page size lives in the freelist DB record's pad field of either
    // meta page; sanity-check it before using it to locate meta page 1.
    let page_size = {
        let meta = &buf[PAGE_HEADER_SIZE..];
        u32_at(meta, 0x18)
    };
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(format!("implausible LMDB page size: {page_size}"));
    }

    let meta1 = buf
        .get(page_size as usize..)
        .and_then(parse_meta_page)
        .ok_or("file too small for the second LMDB meta page")?;

    let env_flags = {
        let meta = &buf[PAGE_HEADER_SIZE..];
        u16_at(meta, 0x18 + 0x04)
    };

    let active_meta = usize::from(meta1.txn_id > meta0.txn_id);
    Ok(MetaReport {
        page_size,
        env_flags,
        active_meta,
        meta_pages: [meta0, meta1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use heed::types::Bytes;
    use heed::{Database, EnvOpenOptions};

    /// Build a real LMDB env with heed and check the raw parser against it.
    #[test]
    fn parses_real_lmdb_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(10 * 1024 * 1024)
                .max_dbs(1)
                .open(tmp.path())
                .unwrap()
        };
        let mut wtxn = env.write_txn().unwrap();
        let db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, None).unwrap();
        db.put(&mut wtxn, b"key-1", b"value-1").unwrap();
        db.put(&mut wtxn, b"key-2", b"value-2").unwrap();
        wtxn.commit().unwrap();

        let report = parse_meta(&tmp.path().join("data.mdb")).unwrap();
        let active = report.active();

        assert!(active.magic_ok);
        assert_eq!(active.format_version, 1);
        assert_eq!(report.page_size as usize, page_size::get());
        assert_eq!(active.main_db.entries, 2);
        assert_eq!(active.txn_id, env.info().last_txn_id as u64);
        assert!(active.main_db.root_page.is_some());
        // A fresh env has never freed a page: freelist is empty.
        assert_eq!(active.freelist_db.entries, 0);
        assert!(active.freelist_db.root_page.is_none());
    }

    #[test]
    fn rejects_non_lmdb_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bogus = tmp.path().join("bogus.mdb");
        std::fs::write(&bogus, vec![0u8; 4096]).unwrap();
        assert!(parse_meta(&bogus).is_err());
    }
}
