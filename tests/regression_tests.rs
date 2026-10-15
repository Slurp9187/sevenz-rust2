#![cfg(feature = "compress")]

use std::io::{Cursor, ErrorKind};

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderConfiguration, EncoderMethod, Error,
    Password,
    encoder_options::{Lzma2Options, LzmaOptions},
};

fn assert_dictionary_rejected(config: EncoderConfiguration) {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![config]);

    let result = writer.push_archive_entry(ArchiveEntry::new_file("data"), Some(&b"x"[..]));
    assert!(matches!(
        result,
        Err(Error::Io(error, _)) if error.kind() == ErrorKind::InvalidInput
    ));
}

#[test]
fn lzma_rejects_unsupported_dictionary() {
    for level in [0, 6] {
        for dict_size in [1 << 30, 1 << 31, u32::MAX] {
            let mut options = LzmaOptions::from_level(level);
            options.set_dictionary_size(dict_size);
            assert_dictionary_rejected(options.into());
        }
        #[cfg(target_pointer_width = "32")]
        {
            let mut options = LzmaOptions::from_level(level);
            options.set_dictionary_size(268435455);
            assert_dictionary_rejected(options.into());
        }
    }
}

#[test]
fn lzma2_rejects_unsupported_dictionary() {
    for level in [0, 6] {
        for threads in [0, 1, 2] {
            for dict_size in [1 << 30, 1 << 31, u32::MAX] {
                let mut options = Lzma2Options::from_level_mt(level, threads, 65536);
                options.set_dictionary_size(dict_size);
                assert_dictionary_rejected(options.into());
            }
            #[cfg(target_pointer_width = "32")]
            {
                let mut options = Lzma2Options::from_level_mt(level, threads, 65536);
                options.set_dictionary_size(268435455);
                assert_dictionary_rejected(options.into());
            }
        }
    }
}

// An empty file stored with COPY packs to a zero-byte stream, whose CRC is 0. Writing it next
// to non-empty files once wrote which pack CRCs were defined but not the CRCs themselves,
// leaving an archive neither this crate nor 7-Zip could open.
#[test]
fn copy_archive_with_an_empty_file_reads_back() {
    let cases: [&[&[u8]]; 4] = [
        &[b"aaa", b"", b"bbb"],
        &[b"", b"aaa", b"bbb"],
        &[b"aaa", b"bbb", b""],
        &[b""],
    ];
    for contents in cases {
        let mut archive = Vec::new();
        {
            let mut writer = ArchiveWriter::new(Cursor::new(&mut archive)).unwrap();
            writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
            for (i, data) in contents.iter().enumerate() {
                writer
                    .push_archive_entry(ArchiveEntry::new_file(&format!("{i}")), Some(*data))
                    .unwrap();
            }
            writer.finish().unwrap();
        }

        let mut reader = ArchiveReader::new(Cursor::new(archive), Password::empty()).unwrap();
        for (i, data) in contents.iter().enumerate() {
            assert_eq!(
                reader.read_file(&format!("{i}")).unwrap(),
                *data,
                "{contents:?}"
            );
        }
    }
}
