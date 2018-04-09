


struct MemAreaChunk<'a> {
    next: &'a MemAreaChunk,
    mem_size: usize,
    next_mem: RawPointer,
}
