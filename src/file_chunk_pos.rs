use std::ops::Range;

/// Represents single file chunk bounds, defined by chunk starting byte and chunk length.
/// Also stores this chunk's index in its file.
#[derive(Copy, Clone, Debug)]
pub(crate) struct FileChunkPosition {
    /// Chunk index.
    pub index: u32,

    /// Starting byte position for this chunk.
    pub start_position: u64,

    /// Chunk size.
    pub chunk_size: u32,
}

impl FileChunkPosition {
    pub fn as_range(&self) -> Range<usize> {
        self.start_position as usize..self.next_chunk_start() as usize
    }

    pub fn next_chunk_start(&self) -> u64 {
        self.start_position + self.chunk_size as u64
    }
}

/// Used as an iterator calculating file chunk positions from the given file size and chunk size. Who needs for loops, right?
#[derive(Copy, Clone, Debug)]
pub(crate) struct FileChunkPositions {
    current_index: u32,
    current_offset: u64,
    chunk_size: u32,
    file_size: u64,
}

impl FileChunkPositions {
    pub fn new(chunk_size: u32, file_size: u64) -> FileChunkPositions {
        if chunk_size == 0 {
            panic!("Chunk size cannot be 0");
        }

        FileChunkPositions {
            current_index: 0,
            current_offset: 0,
            chunk_size,
            file_size,
        }
    }
}

impl Iterator for FileChunkPositions {
    type Item = FileChunkPosition;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_size == 0 {
            return None;
        }

        let last_index = ((self.file_size - 1) / self.chunk_size as u64) as u32;
        if self.current_index <= last_index {
            let maybe_next_offset = self.current_offset.checked_add(self.chunk_size as u64);
            let current_chunk_size = if maybe_next_offset.is_none() || maybe_next_offset.unwrap() > self.file_size {
                (self.file_size - self.current_offset) as u32
            } else {
                self.chunk_size
            };

            let result = FileChunkPosition {
                index: self.current_index,
                start_position: self.current_offset,
                chunk_size: current_chunk_size,
            };

            self.current_index += 1;
            self.current_offset = maybe_next_offset.unwrap_or(self.file_size);
            Some(result)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn even_offsets_should_work() {
        let data = (0..4).collect::<Vec<u8>>();
        let offsets = FileChunkPositions::new(2, data.len() as u64).collect::<Vec<FileChunkPosition>>();
        let sliced = offsets
            .iter()
            .map(|offset| {
                let indices =
                    offset.start_position as usize..(offset.start_position + offset.chunk_size as u64) as usize;
                indices.map(|i| data[i]).collect::<Vec<u8>>()
            })
            .collect::<Vec<Vec<u8>>>();

        assert_eq!(offsets.len(), 2);
        assert_eq!(sliced.len(), 2);
        assert_eq!(sliced[0], vec![0, 1]);
        assert_eq!(sliced[1], vec![2, 3]);
    }

    #[test]
    fn uneven_offsets_should_work() {
        let data = (0..5).collect::<Vec<u8>>();
        let offsets = FileChunkPositions::new(2, data.len() as u64).collect::<Vec<FileChunkPosition>>();
        let sliced = offsets
            .iter()
            .map(|offset| {
                let indices =
                    offset.start_position as usize..(offset.start_position + offset.chunk_size as u64) as usize;
                indices.map(|i| data[i]).collect::<Vec<u8>>()
            })
            .collect::<Vec<Vec<u8>>>();

        assert_eq!(offsets.len(), 3);
        assert_eq!(sliced.len(), 3);
        assert_eq!(sliced[0], vec![0, 1]);
        assert_eq!(sliced[1], vec![2, 3]);
        assert_eq!(sliced[2], vec![4]);
    }

    #[test]
    fn offsets_for_zero_is_zero() {
        let zero = FileChunkPositions::new(1, 0u64).collect::<Vec<FileChunkPosition>>();
        assert!(zero.is_empty());
    }

    #[test]
    fn chunk_size_bigger_than_file_should_return_correctly_sized_offset() {
        let size = 100u32;
        let offsets = FileChunkPositions::new(1024 * 1024, size as u64).collect::<Vec<FileChunkPosition>>();
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets[0].chunk_size, size);
    }
}
