#![cfg(all(feature = "compress", feature = "aes256"))]

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

use sevenz_rust2::{encoder_options::AesEncoderOptions, *};

/// Distinct contents, so a mix-up between entries shows: compressible, then not.
fn content(name: &str) -> Vec<u8> {
    let mut out = name.repeat(2048).into_bytes();
    let mut state = (name.len() as u32).wrapping_mul(2_654_435_761) | 1;
    out.extend((0..20_000).map(|_| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
    }));
    out
}

/// One solid block of three entries, two blocks of one entry each, a directory and an empty
/// file, written with `methods` (and `password`'s AES before them, header included, when given).
fn source_archive(methods: Vec<EncoderConfiguration>, password: Option<&str>) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut all = Vec::new();
    if let Some(password) = password {
        all.push(AesEncoderOptions::new(Password::from(password)).into());
    }
    all.extend(methods);
    writer.set_content_methods(all);
    let solid = ["a.bin", "b.bin", "c.bin"];
    writer
        .push_archive_entries(
            solid.iter().map(|n| ArchiveEntry::new_file(n)).collect(),
            solid
                .iter()
                .map(|n| Cursor::new(content(n)).into())
                .collect(),
        )
        .unwrap();
    for name in ["d.bin", "e.bin"] {
        writer
            .push_archive_entry(
                ArchiveEntry::new_file(name),
                Some(Cursor::new(content(name))),
            )
            .unwrap();
    }
    writer
        .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory("folder"), None)
        .unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file("empty.bin"), Some(&b""[..]))
        .unwrap();
    writer.finish().unwrap().into_inner()
}

/// Every entry as `(name, contents)`, sorted by name.
fn entries(archive: &[u8], password: &str) -> Vec<(String, Vec<u8>)> {
    let mut reader = ArchiveReader::new(Cursor::new(archive), Password::from(password)).unwrap();
    let mut entries = Vec::new();
    reader
        .for_each_entries(|entry, data| {
            let mut buffer = Vec::new();
            data.read_to_end(&mut buffer)?;
            entries.push((entry.name.clone(), buffer));
            Ok(true)
        })
        .unwrap();
    entries.sort();
    entries
}

/// Every block of `source` (opened with `from`) rewrapped under `to` (or bare), and the entries
/// with no data pushed as they are. Returns the archive, and each block's stream beneath the AES
/// layer as the rewrap carried it.
fn rewrap(source: &[u8], from: &str, to: Option<&str>) -> (Vec<u8>, Vec<Vec<u8>>) {
    let from = Password::from(from);
    let mut source = Cursor::new(source);
    let archive = Archive::read(&mut source, &from).unwrap();
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let wrap = to.map(|to| AesEncoderOptions::new(Password::from(to)));
    if let Some(wrap) = &wrap {
        // The header goes under the same password.
        writer.set_content_methods(vec![wrap.clone().into()]);
    }
    let mut carried = Vec::new();
    for block in 0..archive.blocks.len() {
        let mut inner = Vec::new();
        writer
            .push_rewrapped_block(&archive, block, &mut source, &from, wrap.as_ref(), |c| {
                inner.extend_from_slice(c)
            })
            .unwrap();
        carried.push(inner);
    }
    for (file, block) in archive
        .files
        .iter()
        .zip(&archive.stream_map.file_block_index)
    {
        if block.is_none() {
            writer
                .push_archive_entry::<&[u8]>(file.clone(), None)
                .unwrap();
        }
    }
    (writer.finish().unwrap().into_inner(), carried)
}

/// Each block's stream beneath its AES layer, read back.
fn inner_streams(archive: &[u8], password: &str) -> Vec<Vec<u8>> {
    let password = Password::from(password);
    let mut source = Cursor::new(archive);
    let read = Archive::read(&mut source, &password).unwrap();
    (0..read.blocks.len())
        .map(|block| {
            let mut inner = Vec::new();
            read_inner_packed_stream(&read, block, &mut source, &password, |c| {
                inner.extend_from_slice(c)
            })
            .unwrap();
            inner
        })
        .collect()
}

fn aes_count(archive: &[u8], password: &str) -> usize {
    let read = Archive::read(&mut Cursor::new(archive), &Password::from(password)).unwrap();
    read.blocks
        .iter()
        .flat_map(|b| &b.coders)
        .filter(|c| c.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
        .count()
}

/// Encrypting a plain archive: the same entries under the password, the packed streams beneath
/// the new AES layer the plain archive's own, and no listing without the password.
///
/// Falsify: skip the `enc.encrypt_blocks` in `push_rewrapped_block`; nothing reads.
#[test]
fn a_plain_archive_is_encrypted_without_recompressing() {
    let plain = source_archive(vec![EncoderMethod::LZMA2.into()], None);
    let (encrypted, carried) = rewrap(&plain, "", Some("new"));

    assert_eq!(entries(&encrypted, "new"), entries(&plain, ""));
    let blocks = Archive::read(&mut Cursor::new(&encrypted), &Password::from("new"))
        .unwrap()
        .blocks
        .len();
    assert_eq!(
        aes_count(&encrypted, "new"),
        blocks,
        "a block left unencrypted"
    );
    assert!(Archive::read(&mut Cursor::new(&encrypted), &Password::empty()).is_err());
    // Not one byte recompressed: beneath the AES layer, the plain archive's packed streams.
    assert_eq!(carried, inner_streams(&plain, ""));
    assert_eq!(inner_streams(&encrypted, "new"), carried);
}

/// Changing the password: the old one opens nothing, the new one opens the same entries, and
/// every block has an IV of its own.
#[test]
fn an_encrypted_archive_changes_its_password_without_recompressing() {
    let old = source_archive(vec![EncoderMethod::LZMA2.into()], Some("old"));
    let (new, carried) = rewrap(&old, "old", Some("new"));

    assert_eq!(entries(&new, "new"), entries(&old, "old"));
    assert!(Archive::read(&mut Cursor::new(&new), &Password::from("old")).is_err());
    assert_eq!(carried, inner_streams(&old, "old"));
    assert_eq!(inner_streams(&new, "new"), carried);

    let read = Archive::read(&mut Cursor::new(&new), &Password::from("new")).unwrap();
    let mut ivs: Vec<Vec<u8>> = read
        .blocks
        .iter()
        .map(|b| b.coders[0].properties()[18..34].to_vec())
        .collect();
    ivs.sort();
    ivs.dedup();
    assert_eq!(ivs.len(), read.blocks.len(), "an IV is shared");
}

/// Decrypting: the same entries with no password, and no AES coder left.
#[test]
fn an_encrypted_archive_is_decrypted_without_recompressing() {
    let encrypted = source_archive(vec![EncoderMethod::LZMA2.into()], Some("pw"));
    let (plain, carried) = rewrap(&encrypted, "pw", None);

    assert_eq!(entries(&plain, ""), entries(&encrypted, "pw"));
    assert_eq!(aes_count(&plain, ""), 0);
    assert_eq!(inner_streams(&plain, ""), carried);
}

/// A wrong password is not seen by the rewrap: AES has no check of its own, so it copies garbage
/// as faithfully as the stream, and the garbage reads back the same beneath no AES layer. Only
/// decoding the result shows it, which is why a host must decode before it trusts a rewrap.
#[test]
fn a_wrong_password_rewraps_garbage_that_only_decoding_refuses() {
    let encrypted = source_archive(vec![EncoderMethod::LZMA2.into()], Some("pw"));
    // The header is opened with the right password; the blocks with a wrong one.
    let mut source = Cursor::new(&encrypted);
    let archive = Archive::read(&mut source, &Password::from("pw")).unwrap();
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut carried = Vec::new();
    for block in 0..archive.blocks.len() {
        let mut inner = Vec::new();
        writer
            .push_rewrapped_block(
                &archive,
                block,
                &mut source,
                &Password::from("wrong"),
                None,
                |c| inner.extend_from_slice(c),
            )
            .unwrap();
        carried.push(inner);
    }
    let garbage = writer.finish().unwrap().into_inner();
    // Copied faithfully: what the wrong key gave is what lies in the result.
    assert_eq!(inner_streams(&garbage, ""), carried);
    assert_ne!(carried, inner_streams(&encrypted, "pw"));
    // And decoding refuses it.
    let mut reader = ArchiveReader::new(Cursor::new(&garbage), Password::empty()).unwrap();
    assert!(
        reader
            .for_each_entries(|_, data| {
                std::io::copy(data, &mut std::io::sink())?;
                Ok(true)
            })
            .is_err()
    );
}

/// A block encrypted and not compressed (AES alone) decrypts to its entries stored, under a
/// COPY coder, and changes its password as one coder.
///
/// Falsify: drop the COPY coder `push_rewrapped_block` adds to an empty chain; the decrypted
/// archive's blocks then have no coders and nothing reads.
#[test]
fn an_aes_only_block_decrypts_to_a_stored_one() {
    let encrypted = source_archive(Vec::new(), Some("pw"));
    let want = entries(&encrypted, "pw");
    let (plain, _) = rewrap(&encrypted, "pw", None);
    assert_eq!(entries(&plain, ""), want);
    let read = Archive::read(&mut Cursor::new(&plain), &Password::empty()).unwrap();
    assert!(
        read.blocks
            .iter()
            .all(|b| b.coders.len() == 1
                && b.coders[0].encoder_method_id() == EncoderMethod::ID_COPY)
    );
    let (rotated, _) = rewrap(&encrypted, "pw", Some("new"));
    assert_eq!(entries(&rotated, "new"), want);
}

/// A chain of two coders keeps both, the AES layer going on beneath them.
#[test]
fn a_filter_chain_keeps_its_coders() {
    let methods = vec![
        EncoderMethod::BCJ_X86_FILTER.into(),
        EncoderMethod::LZMA2.into(),
    ];
    let plain = source_archive(methods, None);
    let (encrypted, _) = rewrap(&plain, "", Some("pw"));
    let read = Archive::read(&mut Cursor::new(&encrypted), &Password::from("pw")).unwrap();
    assert_eq!(read.blocks[0].coders.len(), 3);
    assert_eq!(entries(&encrypted, "pw"), entries(&plain, ""));
    let (back, _) = rewrap(&encrypted, "pw", None);
    assert_eq!(entries(&back, ""), entries(&plain, ""));
}

fn resource(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resources")
            .join(name),
    )
    .unwrap()
}

/// An archive 7-Zip encrypted, in 7-Zip's own coder order, changes its password and decrypts.
#[test]
fn a_seven_zip_encrypted_archive_rewraps() {
    let original = resource("aes_small_test.7z");
    let password = "iBlm8NTigvru0Jr0";
    let want = entries(&original, password);
    let (rotated, _) = rewrap(&original, password, Some("new"));
    assert_eq!(entries(&rotated, "new"), want);
    let (plain, _) = rewrap(&original, password, None);
    assert_eq!(entries(&plain, ""), want);
}

/// A BCJ2 block reads four packed streams, so it is refused by name, before anything is written.
#[test]
fn a_bcj2_block_is_not_rewrappable() {
    let bcj2 = resource("7za433_7zip_lzma2_bcj2.7z");
    let mut source = Cursor::new(&bcj2);
    let archive = Archive::read(&mut source, &Password::empty()).unwrap();
    let refusals: Vec<_> = archive
        .blocks
        .iter()
        .filter_map(|b| b.rewrappable().err())
        .collect();
    assert!(
        refusals.contains(&NotRewrappable::PackedStreams(4)),
        "{refusals:?}"
    );
    let block = archive
        .blocks
        .iter()
        .position(|b| b.rewrappable().is_err())
        .unwrap();
    let writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let before = writer.finish().unwrap().into_inner().len();
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    assert!(
        writer
            .push_rewrapped_block(
                &archive,
                block,
                &mut source,
                &Password::empty(),
                None,
                |_| ()
            )
            .is_err()
    );
    assert_eq!(writer.finish().unwrap().into_inner().len(), before);
}

fn seven_zip() -> Option<PathBuf> {
    ["7zz", "7z", r"C:\Program Files\7-Zip\7z.exe"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| {
            Command::new(path)
                .arg("i")
                .output()
                .is_ok_and(|output| output.status.success())
        })
}

/// 7-Zip tests each rewrap OK and refuses the old password. Skipped when no 7-Zip is installed.
#[test]
fn seven_zip_tests_each_rewrap_ok() {
    let Some(seven_zip) = seven_zip() else {
        eprintln!("no 7-Zip installed, skipping");
        return;
    };
    let plain = source_archive(vec![EncoderMethod::LZMA2.into()], None);
    let (encrypted, _) = rewrap(&plain, "", Some("pw1"));
    let (rotated, _) = rewrap(&encrypted, "pw1", Some("pw2"));
    let (decrypted, _) = rewrap(&rotated, "pw2", None);
    let directory = tempfile::tempdir().unwrap();
    let test = |name: &str, bytes: &[u8], password: &str| {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let output = Command::new(&seven_zip)
            .arg("t")
            .arg(format!("-p{password}"))
            .arg(&path)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        (output.status.success(), stdout)
    };
    for (name, bytes, password) in [
        ("encrypted.7z", &encrypted, "pw1"),
        ("rotated.7z", &rotated, "pw2"),
        ("decrypted.7z", &decrypted, ""),
    ] {
        let (ok, stdout) = test(name, bytes, password);
        assert!(
            ok && stdout.contains("Everything is Ok"),
            "{name}: {stdout}"
        );
        assert!(stdout.contains("Files: 6"), "{name}: {stdout}");
    }
    let (ok, _) = test("rotated-old.7z", &rotated, "pw1");
    assert!(!ok, "the old password opened the rotated archive");
}
