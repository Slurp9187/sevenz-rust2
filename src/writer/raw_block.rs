//! Where a block of an existing archive lies and what it holds, for the writers that copy one
//! across without decoding it ([`ArchiveWriter::push_raw_block`] and the rewrap).

use super::*;

/// The first packed stream of block `block_index`.
pub(crate) fn first_pack_stream(archive: &Archive, block_index: usize, op: &str) -> Result<usize> {
    archive
        .stream_map
        .block_first_pack_stream_index
        .get(block_index)
        .copied()
        .ok_or_else(|| unmapped(block_index, op))
}

/// Where packed stream `pack_stream` (of block `block_index`) lies in its archive, and its size.
pub(crate) fn pack_stream_span(
    archive: &Archive,
    block_index: usize,
    pack_stream: usize,
    op: &str,
) -> Result<(u64, u64)> {
    let (Some(&size), Some(&stream_offset)) = (
        archive.pack_sizes.get(pack_stream),
        archive.stream_map.pack_stream_offsets.get(pack_stream),
    ) else {
        return Err(unmapped(block_index, op));
    };
    // The header's offsets are not bounded when it is read.
    let offset = SIGNATURE_HEADER_SIZE
        .checked_add(archive.pack_pos)
        .and_then(|offset| offset.checked_add(stream_offset))
        .ok_or_else(|| {
            Error::other(format!(
                "{op}: block {block_index} lies past the end of any file"
            ))
        })?;
    Ok((offset, size))
}

/// The stream map is only built along with the files, so an archive without a `FilesInfo` has
/// blocks and no map of them.
fn unmapped(block_index: usize, op: &str) -> Error {
    Error::other(format!(
        "{op}: block {block_index} is missing from the stream map"
    ))
}

/// Block `block_index`'s sub-streams (its entries' sizes and CRCs) and its entries, each named
/// by `rename`.
pub(crate) fn raw_block_entries(
    archive: &Archive,
    block_index: usize,
    rename: &mut impl FnMut(&ArchiveEntry) -> String,
    op: &str,
) -> Result<(Vec<u64>, Vec<u32>, Vec<ArchiveEntry>)> {
    let block = archive
        .blocks
        .get(block_index)
        .ok_or_else(|| Error::other(format!("{op}: no block {block_index}")))?;
    let map = &archive.stream_map;
    let first_sub_stream = *map
        .block_first_sub_stream_index
        .get(block_index)
        .ok_or_else(|| unmapped(block_index, op))?;
    let sub_streams = first_sub_stream..first_sub_stream + block.num_unpack_sub_streams;
    let info = archive.sub_streams_info.as_ref();
    let mut sub_stream_sizes = Vec::with_capacity(sub_streams.len());
    let mut sub_stream_crcs = Vec::with_capacity(sub_streams.len());
    for index in sub_streams {
        let crc = match info {
            Some(info) if info.has_crc.contains(index) => info.crcs[index] as u32,
            // A lone sub-stream may carry its CRC on the block instead.
            _ if block.num_unpack_sub_streams == 1 && block.has_crc => block.crc as u32,
            _ => {
                return Err(Error::other(format!(
                    "{op}: block {block_index} has an entry without a CRC"
                )));
            }
        };
        sub_stream_crcs.push(crc);
        sub_stream_sizes
            .push(info.map_or(block.get_unpack_size(), |info| info.unpack_sizes[index]));
    }

    // Its entries, the files with data in it, in order. An empty entry between two of a solid
    // block's may be mapped to it too, but it has no sub-stream there.
    let entries: Vec<ArchiveEntry> = archive
        .files
        .iter()
        .zip(&map.file_block_index)
        .filter(|(entry, block)| entry.has_stream && **block == Some(block_index))
        .map(|(entry, _)| ArchiveEntry {
            name: rename(entry),
            ..entry.clone()
        })
        .collect();
    if entries.len() != block.num_unpack_sub_streams {
        return Err(Error::other(format!(
            "{op}: block {block_index} has {} entries for {} sub-streams",
            entries.len(),
            block.num_unpack_sub_streams
        )));
    }
    Ok((sub_stream_sizes, sub_stream_crcs, entries))
}
