//! Copying a block of an existing archive with its AES layer added, replaced or removed, and
//! never its compression touched: the packed stream under the AES layer goes across as it is.
//!
//! [`ArchiveWriter::push_raw_block`] copies a block as it is encoded, AES included. A host that
//! re-encrypts an archive under a new password, encrypts a plain one, or decrypts one, would
//! otherwise decode every entry and compress it again. These copy the packed stream beneath the
//! outer AES coder instead, so a rewrite costs a read, the AES pass and a write.

use std::io::{Read, Seek, SeekFrom, Write};

use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, array::Array},
};
use zeroize::Zeroize;

use super::{raw_block::*, *};
use crate::{
    Block, Coder, Password, block::BindPair, encoder_options::AesEncoderOptions,
    encryption::get_aes_key,
};

/// Why a block cannot be rewrapped: the chain it is encoded with is not one coder after
/// another over one packed stream, or AES sits somewhere other than on the packed stream.
/// The host decodes and re-encodes such a block instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRewrappable {
    /// The block reads more than one packed stream (BCJ2 does).
    PackedStreams(usize),
    /// A coder takes or gives more than one stream.
    MultiStreamCoder,
    /// The coders do not form one chain from the packed stream to the output.
    NotOneChain,
    /// An AES coder that is not the one reading the packed stream.
    InnerAes,
    /// The block has no coders.
    NoCoders,
}

impl std::fmt::Display for NotRewrappable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PackedStreams(n) => write!(f, "the block reads {n} packed streams"),
            Self::MultiStreamCoder => f.write_str("a coder takes or gives more than one stream"),
            Self::NotOneChain => f.write_str("the coders do not form one chain"),
            Self::InnerAes => f.write_str("an AES coder is not on the packed stream"),
            Self::NoCoders => f.write_str("the block has no coders"),
        }
    }
}

impl std::error::Error for NotRewrappable {}

/// A block's coders from the packed stream out, each with the size it unpacks to.
fn chain(block: &Block) -> std::result::Result<Vec<(&Coder, u64)>, NotRewrappable> {
    if block.coders.is_empty() {
        return Err(NotRewrappable::NoCoders);
    }
    if block.packed_streams.len() != 1 {
        return Err(NotRewrappable::PackedStreams(block.packed_streams.len()));
    }
    if block
        .coders
        .iter()
        .any(|c| c.num_in_streams != 1 || c.num_out_streams != 1)
    {
        return Err(NotRewrappable::MultiStreamCoder);
    }
    let chain: Vec<(&Coder, u64)> = block
        .ordered_coder_iter()
        .map(|(index, coder)| (coder, block.get_unpack_size_at_index(index)))
        .collect();
    if chain.len() != block.coders.len() || block.bind_pairs.len() + 1 != block.coders.len() {
        return Err(NotRewrappable::NotOneChain);
    }
    if chain.iter().skip(1).any(|(c, _)| is_aes(c)) {
        return Err(NotRewrappable::InnerAes);
    }
    Ok(chain)
}

fn is_aes(coder: &Coder) -> bool {
    coder.encoder_method_id() == EncoderMethod::ID_AES256_SHA256
}

impl Block {
    /// Whether [`ArchiveWriter::push_rewrapped_block`] can copy this block, and why not when it
    /// cannot.
    pub fn rewrappable(&self) -> std::result::Result<(), NotRewrappable> {
        chain(self).map(drop)
    }
}

/// The bytes a rewrap moves at a time: a whole number of AES blocks.
const CHUNK: usize = 64 * 1024;

/// One block's packed stream read through its outer AES coder, if it has one: what lies beneath
/// the encryption, in chunks of [`CHUNK`], each decrypted in one call.
struct InnerPacked<'a, R> {
    source: &'a mut R,
    /// Packed bytes still to read.
    left: u64,
    /// Bytes beneath the AES layer still owed; the rest of the last AES block is padding.
    owed: u64,
    dec: Option<cbc::Decryptor<Aes256>>,
}

impl<'a, R: Read + Seek> InnerPacked<'a, R> {
    /// Open block `block_index`'s packed stream in `source`. `password` opens its AES layer.
    fn open(
        archive: &Archive,
        block_index: usize,
        source: &'a mut R,
        password: &Password,
        op: &str,
    ) -> Result<(Self, Vec<(Coder, u64)>)> {
        let block = archive
            .blocks
            .get(block_index)
            .ok_or_else(|| Error::other(format!("{op}: no block {block_index}")))?;
        let chain = chain(block).map_err(|e| Error::other(format!("{op}: {e}")))?;
        let pack_stream = first_pack_stream(archive, block_index, op)?;
        let (offset, size) = pack_stream_span(archive, block_index, pack_stream, op)?;
        source.seek(SeekFrom::Start(offset))?;
        let (dec, owed, rest) = match chain.split_first() {
            Some(((aes, owed), rest)) if is_aes(aes) => {
                if size % 16 != 0 || *owed > size || size - *owed >= 16 {
                    return Err(Error::other(format!(
                        "{op}: block {block_index}'s AES stream does not fit its packed size"
                    )));
                }
                let (key, iv) = get_aes_key(aes.properties(), password.as_slice())?;
                let dec = cbc::Decryptor::<Aes256>::new(&Array::from(*key), &iv.into());
                (Some(dec), *owed, rest)
            }
            _ => (None, size, &chain[..]),
        };
        let rest = rest.iter().map(|(c, n)| ((*c).clone(), *n)).collect();
        Ok((
            Self {
                source,
                left: size,
                owed,
                dec,
            },
            rest,
        ))
    }

    /// The next chunk of what lies beneath the AES layer into `buf` (at least [`CHUNK`] long),
    /// or 0 at the end.
    fn next(&mut self, buf: &mut [u8]) -> Result<usize> {
        let want = usize::try_from(self.left.min(CHUNK as u64)).unwrap_or(CHUNK);
        if want == 0 {
            return Ok(0);
        }
        self.source.read_exact(&mut buf[..want]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::other("the packed stream is truncated")
            } else {
                Error::from(e)
            }
        })?;
        self.left -= want as u64;
        if let Some(dec) = &mut self.dec {
            let (blocks, tail) = Array::slice_as_chunks_mut(&mut buf[..want]);
            debug_assert!(tail.is_empty(), "packed size is a multiple of 16");
            dec.decrypt_blocks(blocks);
        }
        let n = usize::try_from(self.owed.min(want as u64)).unwrap_or(want);
        self.owed -= n as u64;
        Ok(n)
    }
}

/// A chunk buffer wiped when dropped: what passes through it is compressed plaintext.
struct WipedChunk(Box<[u8]>);

impl WipedChunk {
    fn new() -> Self {
        Self(vec![0u8; CHUNK].into_boxed_slice())
    }
}

impl Drop for WipedChunk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Read block `block_index`'s packed stream in `source` through its outer AES coder (opened
/// with `password`), if it has one, handing `inspect` each chunk of what lies beneath it. Returns
/// how many bytes that was. For a host that checks a rewrap: the stream beneath the AES layer
/// is what [`ArchiveWriter::push_rewrapped_block`] promises to carry across unchanged.
///
/// The chunks are wiped after `inspect` sees them.
///
/// # Errors
/// If the block is not [rewrappable](Block::rewrappable), its packed stream lies outside
/// `source`, or its AES properties cannot be read. A wrong password is not an error here: AES
/// has no check of its own, so only decoding the block shows it.
pub fn read_inner_packed_stream<R: Read + Seek>(
    archive: &Archive,
    block_index: usize,
    source: &mut R,
    password: &Password,
    mut inspect: impl FnMut(&[u8]),
) -> Result<u64> {
    let (mut inner, _) = InnerPacked::open(
        archive,
        block_index,
        source,
        password,
        "read_inner_packed_stream",
    )?;
    let mut chunk = WipedChunk::new();
    let mut total = 0u64;
    loop {
        let n = inner.next(&mut chunk.0)?;
        if n == 0 && inner.left == 0 {
            return Ok(total);
        }
        inspect(&chunk.0[..n]);
        total += n as u64;
    }
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Copy a block of an existing archive into this one without decoding it, taking off its
    /// AES layer and, with `wrap`, putting a new one on.
    ///
    /// The packed stream beneath the block's outer AES coder (opened with `source_password`), or
    /// the whole packed stream when it has none, is copied byte for byte: encrypted under `wrap`
    /// with a fresh IV when given, or written as it is. Its other coders, sizes and CRCs, and
    /// its entries, are carried over as [`push_raw_block`](Self::push_raw_block) carries them.
    /// So `wrap` with an encrypted source changes its password, `wrap` with a plain one
    /// encrypts it, and no `wrap` with an encrypted one decrypts it.
    ///
    /// `inspect` sees each chunk of the stream beneath the AES layer, as it passes, for a host
    /// that checks the copy against [`read_inner_packed_stream`] of the result. The chunks are
    /// wiped after.
    ///
    /// A wrong `source_password` is not detected here: AES has no check of its own, and the
    /// garbage it gives is copied as faithfully as the right stream. Only decoding the result
    /// shows it (each entry's CRC), so a host must decode the result before trusting it.
    ///
    /// # Errors
    /// If the block is not [rewrappable](Block::rewrappable), or anything
    /// [`push_raw_block`](Self::push_raw_block) refuses.
    pub fn push_rewrapped_block<R: Read + Seek>(
        &mut self,
        archive: &Archive,
        block_index: usize,
        source: &mut R,
        source_password: &Password,
        wrap: Option<&AesEncoderOptions>,
        mut inspect: impl FnMut(&[u8]),
    ) -> Result<&mut Self> {
        const OP: &str = "push_rewrapped_block";
        let block = archive
            .blocks
            .get(block_index)
            .ok_or_else(|| Error::other(format!("{OP}: no block {block_index}")))?;
        let (sub_stream_sizes, sub_stream_crcs, entries) =
            raw_block_entries(archive, block_index, &mut |e| e.name().to_string(), OP)?;
        let (mut inner, rest) =
            InnerPacked::open(archive, block_index, source, source_password, OP)?;
        let inner_size = inner.owed;

        // The new AES layer: the caller's password and salt, an IV of this block's own.
        let wrap = wrap.map(|options| {
            let mut options = options.clone();
            getrandom::fill(&mut options.iv).expect("Can't generate IV");
            options
        });
        let mut enc = match &wrap {
            Some(options) => {
                let (key, iv) = get_aes_key(&options.properties(), options.password.as_slice())?;
                Some(cbc::Encryptor::<Aes256>::new(
                    &Array::from(*key),
                    &iv.into(),
                ))
            }
            None => None,
        };

        let mut chunk = WipedChunk::new();
        let mut packed_len = 0u64;
        let mut packed_crc = Hasher::new();
        loop {
            let n = inner.next(&mut chunk.0)?;
            if n == 0 && inner.left == 0 {
                break;
            }
            inspect(&chunk.0[..n]);
            let out = match &mut enc {
                Some(enc) => {
                    // Every chunk but the last is whole AES blocks; the last is padded with
                    // zeros, as 7-Zip pads.
                    let padded = n.div_ceil(16) * 16;
                    chunk.0[n..padded].fill(0);
                    let (blocks, _) = Array::slice_as_chunks_mut(&mut chunk.0[..padded]);
                    enc.encrypt_blocks(blocks);
                    &chunk.0[..padded]
                }
                None => &chunk.0[..n],
            };
            self.output.write_all(out)?;
            packed_crc.update(out);
            packed_len += out.len() as u64;
        }
        self.pack_info
            .add_stream(packed_len, Some(packed_crc.finalize()));

        // The chain, from the packed stream out: the new AES coder, then the rest.
        let coder = |method: EncoderMethod, properties: Vec<u8>| {
            let mut coder = Coder::default();
            let id = method.id();
            coder.id_size = id.len();
            coder.decompression_method_id_mut().copy_from_slice(id);
            coder.num_in_streams = 1;
            coder.num_out_streams = 1;
            coder.properties = properties;
            coder
        };
        let mut coders: Vec<(Coder, u64)> = Vec::with_capacity(rest.len() + 1);
        if let Some(options) = &wrap {
            coders.push((
                coder(EncoderMethod::AES256_SHA256, options.properties().to_vec()),
                inner_size,
            ));
        }
        coders.extend(rest);
        // A block that was AES alone, decrypted, is its entries stored: a block needs a coder,
        // and 7-Zip writes a stored one as COPY.
        if coders.is_empty() {
            coders.push((coder(EncoderMethod::COPY, Vec::new()), inner_size));
        }
        let n = coders.len();
        let rewrapped = Block {
            coders: coders.iter().map(|(c, _)| c.clone()).collect(),
            has_crc: block.has_crc,
            crc: block.crc,
            total_input_streams: n,
            total_output_streams: n,
            // Coder i + 1 reads what coder i gives, as `push_archive_entry` writes a chain.
            bind_pairs: (0..n.saturating_sub(1))
                .map(|i| BindPair {
                    in_index: i as u64 + 1,
                    out_index: i as u64,
                })
                .collect(),
            packed_streams: vec![0],
            unpack_sizes: coders.iter().map(|(_, size)| *size).collect(),
            num_unpack_sub_streams: block.num_unpack_sub_streams,
        };
        self.unpack_info.add_raw(
            &rewrapped,
            rewrapped.num_unpack_sub_streams as u64,
            sub_stream_sizes,
            sub_stream_crcs,
        );
        self.files.extend(entries);
        Ok(self)
    }
}
