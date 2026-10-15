//! `set_max_mem_limit_kb` bounds every decoder an archive asks for: the encoded
//! header's and each block's. Its own test binary, because the limit is one
//! setting for the process.

#![cfg(feature = "compress")]

use std::io::Cursor;

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader, ArchiveWriter, Error, Password, set_max_mem_limit_kb,
};

fn archive() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = ArchiveWriter::new(Cursor::new(&mut out)).unwrap();
        writer
            .push_archive_entry(
                ArchiveEntry::new_file("a.txt"),
                Some(Cursor::new(vec![7u8; 4096])),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    out
}

fn read_all(data: &[u8]) -> Result<(), Error> {
    let mut reader = ArchiveReader::new(Cursor::new(data), Password::empty())?;
    reader.for_each_entries(|_, r| {
        std::io::copy(r, &mut std::io::sink())?;
        Ok(true)
    })
}

#[test]
fn a_decoder_over_the_limit_is_refused_and_the_default_reads() {
    let data = archive();
    assert!(read_all(&data).is_ok(), "no limit by default");

    set_max_mem_limit_kb(1);
    let refused = read_all(&data);
    set_max_mem_limit_kb(usize::MAX / 1024);
    assert!(
        matches!(refused, Err(Error::MaxMemLimited { max_kb: 1, .. })),
        "{refused:?}"
    );
    assert!(read_all(&data).is_ok(), "the limit lifts again");
}
