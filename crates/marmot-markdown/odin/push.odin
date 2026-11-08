package markdown

import "base:runtime"

// AST children are usually short. Reserve four slots initially, then double;
// keep the hot append path independent of allocator and source-location helpers.
push :: proc {
	push_one,
	push_many,
	push_text,
}

push_grow :: proc(array: ^[dynamic]$T, required: int) {
	capacity := max(required, max(4, cap(array^) * 2))
	a := (^runtime.Raw_Dynamic_Array)(array)
	allocator := a.allocator
	if allocator.procedure == nil {allocator = context.allocator}
	if allocator.procedure == arena_allocator {
		if capacity > max(int) / size_of(T) {panic("Markdown AST array allocation failed")}
		// Preserve the array's allocator; new capacity is written before it is read.
		bytes := arena_resize(
			(^Parse_Arena)(allocator.data),
			capacity * size_of(T),
			align_of(T),
			a.data,
			a.cap * size_of(T),
		)
		a.data = raw_data(bytes)
		a.cap = capacity
		a.allocator = allocator
		return
	}
	err := non_zero_reserve(array, capacity)
	if err != nil {panic("Markdown AST array allocation failed")}
}

push_one :: #force_inline proc(array: ^[dynamic]$T, item: T) {
	a := (^runtime.Raw_Dynamic_Array)(array)
	if a.len == a.cap {push_grow(array, a.len + 1)}
	// The capacity guard and reserve above establish this initialized slot.
	([^]T)(a.data)[a.len] = item
	a.len += 1
}

push_many :: #force_inline proc(array: ^[dynamic]$T, items: ..T) {
	a := (^runtime.Raw_Dynamic_Array)(array)
	required := a.len + len(items)
	if required > a.cap {push_grow(array, required)}
	if len(items) > 0 {copy(([^]T)(a.data)[a.len:required], items)}
	a.len = required
}

push_text :: #force_inline proc(array: ^[dynamic]u8, text: string) {
	push_many(array, ..transmute([]u8)text)
}
