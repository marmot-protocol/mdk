#+test
package markdown

import "core:testing"

@(test)
ref_map_siphash_vectors :: proc(t: ^testing.T) {
	seed := [2]u64{0x0706050403020100, 0x0f0e0d0c0b0a0908}
	input: [64]u8
	for i in 0 ..< len(input) {input[i] = u8(i)}
	lengths := [?]int{0, 1, 7, 8, 15, 16, 63}
	expected := [?]u64 {
		0x726fdb47dd0e0e31,
		0x74f839c593dc67fd,
		0xab0200f58b01d137,
		0x93f5f5799a932462,
		0xa129ca6149be45e5,
		0x3f2acc7f57c29bdb,
		0x958a324ceb064572,
	}
	for n, i in lengths {
		testing.expect(t, ref_map_hash(string(input[:n]), seed) == expected[i])
	}
}

@(test)
ref_map_growth_upsert_and_string_keys :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	m: RefMap
	_, present := ref_map_get(m, "")
	testing.expect(t, !present && m.count == 0)
	keys: [512]string
	for i in 0 ..< len(keys) {
		bytes := make([]u8, 2)
		bytes[0], bytes[1] = u8(i >> 8), u8(i & 255)
		keys[i] = string(bytes)
		ref_map_set(&m, keys[i], LinkRef{keys[i], "original", true})
	}
	testing.expect(t, m.count == len(keys))
	for key in keys {
		value, ok := ref_map_get(m, key)
		testing.expect(t, ok && value.dest == key && value.title == "original" && value.has_title)
		ref_map_set(&m, key, LinkRef{key, "replacement", false})
	}
	testing.expect(t, m.count == len(keys))
	for key in keys {
		value, ok := ref_map_get(m, key)
		testing.expect(
			t,
			ok && value.dest == key && value.title == "replacement" && !value.has_title,
		)
	}
	for key in ([]string{"", "日本語", "café", "αβ"}) {
		ref_map_set(&m, key, LinkRef{key, "Unicode or empty", true})
		value, ok := ref_map_get(m, key)
		testing.expect(
			t,
			ok && value.dest == key && value.title == "Unicode or empty" && value.has_title,
		)
	}
	testing.expect(t, m.count == len(keys) + 4)
	_, missing := ref_map_get(m, "not present")
	testing.expect(t, !missing)
}

@(test)
int_map_growth_upsert_and_reinsert :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	m: IntMap
	_, present := int_map_get(m, 0)
	int_map_delete(&m, 0)
	testing.expect(t, !present && m.count == 0)
	for i in 0 ..< 512 {int_map_set(&m, i, i * 7)}
	testing.expect(t, m.count == 512)
	for i in 0 ..< 512 {
		value, ok := int_map_get(m, i)
		testing.expect(t, ok && value == i * 7)
		int_map_set(&m, i, -i)
	}
	testing.expect(t, m.count == 512)
	for i := 0; i < 512; i += 3 {int_map_delete(&m, i)}
	testing.expect(t, m.count == 512 - 171)
	int_map_delete(&m, 9999)
	testing.expect(t, m.count == 512 - 171)
	for i in 0 ..< 512 {
		value, ok := int_map_get(m, i)
		if i % 3 == 0 {
			testing.expect(t, !ok)
			int_map_set(&m, i, -i)
		} else {
			testing.expect(t, ok && value == -i)
		}
	}
	testing.expect(t, m.count == 512)
	for i in 0 ..< 512 {
		value, ok := int_map_get(m, i)
		testing.expect(t, ok && value == -i)
		int_map_delete(&m, i)
	}
	testing.expect(t, m.count == 0)
	int_map_set(&m, 0, 99)
	value, ok := int_map_get(m, 0)
	testing.expect(t, ok && value == 99 && m.count == 1)
}

@(test)
int_map_delete_wrapped_collision_chain :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	// Four keys share the final bucket of the initial eight-slot table.
	// Key zero sits at its own home bucket inside their wrapped probe chain.
	keys: [4]int
	found := 0
	for key := 1; found < len(keys); key += 1 {
		if int_map_hash(key) & 7 == 7 {
			keys[found] = key
			found += 1
		}
	}
	m: IntMap
	int_map_set(&m, keys[0], 10)
	int_map_set(&m, 0, 77)
	for i in 1 ..< len(keys) {int_map_set(&m, keys[i], i + 10)}
	int_map_delete(&m, keys[0])
	testing.expect(t, m.count == 4)
	_, deleted := int_map_get(m, keys[0])
	testing.expect(t, !deleted)
	for i in 1 ..< len(keys) {
		value, ok := int_map_get(m, keys[i])
		testing.expect(t, ok && value == i + 10)
	}
	value, ok := int_map_get(m, 0)
	testing.expect(t, ok && value == 77)
	int_map_delete(&m, keys[2])
	int_map_delete(&m, keys[2])
	testing.expect(t, m.count == 3)
	for i in ([]int{1, 3}) {
		value, ok := int_map_get(m, keys[i])
		testing.expect(t, ok && value == i + 10)
	}
	int_map_set(&m, keys[0], 42)
	value, ok = int_map_get(m, keys[0])
	testing.expect(t, ok && value == 42 && m.count == 4)
}
