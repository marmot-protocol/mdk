package markdown

import "base:intrinsics"
import "base:runtime"

ARENA_BLOCK_BYTES :: 16 * 1024
Arena_Block :: struct {
	previous: ^Arena_Block,
}
Parse_Arena :: struct {
	backing: runtime.Allocator,
	blocks:  ^Arena_Block,
	memory:  []u8,
	used:    int,
}
Native_Result :: struct {
	document: Document,
	arena:    Parse_Arena,
}

// The handle and first scratch block share caller-owned memory. Further blocks grow
// without moving AST data; the most recent allocation can resize in place.
arena_allocate :: proc(a: ^Parse_Arena, size, alignment: int) -> []u8 {
	base := uintptr(raw_data(a.memory))
	start := int(runtime.align_forward_uintptr(base + uintptr(a.used), uintptr(alignment)) - base)
	if start > len(a.memory) || size > len(a.memory) - start {
		capacity := max(ARENA_BLOCK_BYTES, size + alignment)
		bytes, err := runtime.mem_alloc_non_zeroed(
			size_of(Arena_Block) + capacity,
			allocator = a.backing,
		)
		if err != nil {panic("Markdown arena allocation failed")}
		block := (^Arena_Block)(raw_data(bytes))
		block.previous = a.blocks
		a.blocks = block
		a.memory = bytes[size_of(Arena_Block):]
		a.used = 0
		base = uintptr(raw_data(a.memory))
		start = int(runtime.align_forward_uintptr(base, uintptr(alignment)) - base)
	}
	a.used = start + size
	return a.memory[start:a.used]
}

arena_resize :: proc(
	a: ^Parse_Arena,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
) -> []u8 {
	if old_memory != nil && uintptr(old_memory) % uintptr(alignment) == 0 {
		if size <= old_size {return ([^]u8)(old_memory)[:size]}
		if uintptr(old_memory) + uintptr(old_size) ==
			   uintptr(raw_data(a.memory)) + uintptr(a.used) &&
		   size - old_size <= len(a.memory) - a.used {
			a.used += size - old_size
			return ([^]u8)(old_memory)[:size]
		}
	}
	bytes := arena_allocate(a, size, alignment)
	if old_size > 0 {copy(bytes, ([^]u8)(old_memory)[:min(size, old_size)])}
	return bytes
}

arena_allocator :: proc(
	state: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	runtime.Allocator_Error,
) {
	a := (^Parse_Arena)(state)
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		bytes := arena_allocate(a, size, alignment)
		if mode == .Alloc {intrinsics.mem_zero(raw_data(bytes), len(bytes))}
		return bytes, nil
	case .Resize, .Resize_Non_Zeroed:
		bytes := arena_resize(a, size, alignment, old_memory, old_size)
		if mode == .Resize &&
		   size > old_size {intrinsics.mem_zero(&bytes[old_size], size - old_size)}
		return bytes, nil
	case .Free:
		// Individual data remains live until the Rust bridge releases the graph.
		return nil, nil
	case .Query_Features:
		(^runtime.Allocator_Mode_Set)(old_memory)^ = {
			.Alloc,
			.Alloc_Non_Zeroed,
			.Resize,
			.Resize_Non_Zeroed,
			.Free,
			.Query_Features,
		}
		return nil, nil
	case .Free_All, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	unreachable()
}

parse_document :: proc(input: string) -> Document {
	doc, refs := parse_blocks(input)
	parse_inlines(&doc, refs)
	return doc
}

// The caller owns this handle until markdown_free, including every AST slice.
@(export)
markdown_parse :: proc "c" (
	data: [^]u8,
	length: int,
	storage: [^]u8,
	capacity: int,
) -> ^Native_Result {
	context = runtime.Context {
		assertion_failure_proc = runtime.default_assertion_failure_proc,
	}
	assert(capacity >= size_of(Native_Result))
	result := (^Native_Result)(storage)
	result^ = Native_Result{}
	result.arena.backing = runtime.heap_allocator()
	result.arena.memory = storage[size_of(Native_Result):capacity]
	context.allocator = runtime.Allocator {
		procedure = arena_allocator,
		data      = &result.arena,
	}
	result.document = parse_document(string(data[:length]))
	return result
}

@(export)
markdown_free :: proc "c" (result: ^Native_Result) {
	context = runtime.Context {
		assertion_failure_proc = runtime.default_assertion_failure_proc,
	}
	block := result.arena.blocks
	for block != nil {
		previous := block.previous
		free(block, result.arena.backing)
		block = previous
	}
}

@(export)
markdown_classify :: proc "c" (data: [^]u8, length: int) -> u32 {
	context = runtime.Context {
		assertion_failure_proc = runtime.default_assertion_failure_proc,
	}
	return u32(classify_link_destination(string(data[:length])))
}
