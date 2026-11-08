package markdown

import "base:runtime"

// Tables share the parse allocator and borrow their keys, just like the AST.
// A zero hash marks an empty reference slot; the low hash bit is reserved.
@(private)
RefMapEntry :: struct {
	hash:  u64,
	key:   string,
	value: LinkRef,
}

@(private)
RefMap :: struct {
	count:   int,
	entries: []RefMapEntry,
	seed:    [2]u64,
}

@(private)
IntMapEntry :: struct {
	key, value: int,
	occupied:   bool,
}

@(private)
IntMap :: struct {
	count:   int,
	entries: []IntMapEntry,
}

@(private)
map_rotate_left :: #force_inline proc(x: u64, n: u32) -> u64 {
	return (x << n) | (x >> (64 - n))
}

@(private)
ref_map_sip_round :: #force_inline proc(v: ^[4]u64) {
	v[0] += v[1]
	v[1] = map_rotate_left(v[1], 13) ~ v[0]
	v[0] = map_rotate_left(v[0], 32)
	v[2] += v[3]
	v[3] = map_rotate_left(v[3], 16) ~ v[2]
	v[0] += v[3]
	v[3] = map_rotate_left(v[3], 21) ~ v[0]
	v[2] += v[1]
	v[1] = map_rotate_left(v[1], 17) ~ v[2]
	v[2] = map_rotate_left(v[2], 32)
}

// SipHash-2-4, with a separate unpredictable key for each reference table.
@(private)
ref_map_hash :: proc(key: string, seed: [2]u64) -> u64 {
	v := [4]u64 {
		0x736f6d6570736575 ~ seed[0],
		0x646f72616e646f6d ~ seed[1],
		0x6c7967656e657261 ~ seed[0],
		0x7465646279746573 ~ seed[1],
	}
	i := 0
	for len(key) - i >= 8 {
		word :=
			u64(key[i]) |
			u64(key[i + 1]) << 8 |
			u64(key[i + 2]) << 16 |
			u64(key[i + 3]) << 24 |
			u64(key[i + 4]) << 32 |
			u64(key[i + 5]) << 40 |
			u64(key[i + 6]) << 48 |
			u64(key[i + 7]) << 56
		v[3] ~= word
		ref_map_sip_round(&v)
		ref_map_sip_round(&v)
		v[0] ~= word
		i += 8
	}
	last := u64(len(key)) << 56
	for j := 0; i + j < len(key); j += 1 {
		last |= u64(key[i + j]) << (8 * u32(j))
	}
	v[3] ~= last
	ref_map_sip_round(&v)
	ref_map_sip_round(&v)
	v[0] ~= last
	v[2] ~= 0xff
	for _ in 0 ..< 4 {ref_map_sip_round(&v)}
	return v[0] ~ v[1] ~ v[2] ~ v[3]
}

@(private)
ref_map_get :: proc(m: RefMap, key: string) -> (LinkRef, bool) {
	if m.count == 0 {return {}, false}
	hash := ref_map_hash(key, m.seed) | 1
	mask := len(m.entries) - 1
	i := int(hash & u64(mask))
	for m.entries[i].hash != 0 {
		entry := &m.entries[i]
		if entry.hash == hash && entry.key == key {return entry.value, true}
		i = (i + 1) & mask
	}
	return {}, false
}

@(private)
ref_map_grow :: proc(m: ^RefMap) {
	old := m.entries
	entries, err := make([]RefMapEntry, max(8, len(old) * 2))
	if err != nil {panic("Markdown reference table allocation failed")}
	mask := len(entries) - 1
	for entry in old {
		if entry.hash == 0 {continue}
		i := int(entry.hash & u64(mask))
		for entries[i].hash != 0 {i = (i + 1) & mask}
		entries[i] = entry
	}
	m.entries = entries
	delete(old)
}

@(private)
ref_map_set :: proc(m: ^RefMap, key: string, value: LinkRef) {
	if len(m.entries) == 0 {
		seed: [2]u64
		bytes := ([^]u8)(raw_data(seed[:]))[:size_of(seed)]
		runtime.rand_bytes(bytes)
		m.seed = seed
		ref_map_grow(m)
	}
	hash := ref_map_hash(key, m.seed) | 1
	mask := len(m.entries) - 1
	i := int(hash & u64(mask))
	for m.entries[i].hash != 0 {
		entry := &m.entries[i]
		if entry.hash == hash && entry.key == key {
			entry.value = value
			return
		}
		i = (i + 1) & mask
	}
	// At most three quarters full, including the new entry.
	if m.count + 1 > len(m.entries) - len(m.entries) / 4 {
		ref_map_grow(m)
		mask = len(m.entries) - 1
		i = int(hash & u64(mask))
		for m.entries[i].hash != 0 {i = (i + 1) & mask}
	}
	m.entries[i] = RefMapEntry{hash, key, value}
	m.count += 1
}

// SplitMix64's finalizer is sufficient for integer offsets and run lengths.
@(private)
int_map_hash :: #force_inline proc(key: int) -> u64 {
	x := u64(key)
	x = (x ~ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ~ (x >> 27)) * 0x94d049bb133111eb
	return x ~ (x >> 31)
}

@(private)
int_map_get :: proc(m: IntMap, key: int) -> (int, bool) {
	if m.count == 0 {return 0, false}
	mask := len(m.entries) - 1
	i := int(int_map_hash(key) & u64(mask))
	for m.entries[i].occupied {
		if m.entries[i].key == key {return m.entries[i].value, true}
		i = (i + 1) & mask
	}
	return 0, false
}

@(private)
int_map_grow :: proc(m: ^IntMap) {
	old := m.entries
	entries, err := make([]IntMapEntry, max(8, len(old) * 2))
	if err != nil {panic("Markdown integer table allocation failed")}
	mask := len(entries) - 1
	for entry in old {
		if !entry.occupied {continue}
		i := int(int_map_hash(entry.key) & u64(mask))
		for entries[i].occupied {i = (i + 1) & mask}
		entries[i] = entry
	}
	m.entries = entries
	delete(old)
}

@(private)
int_map_set :: proc(m: ^IntMap, key, value: int) {
	if len(m.entries) == 0 {int_map_grow(m)}
	mask := len(m.entries) - 1
	i := int(int_map_hash(key) & u64(mask))
	for m.entries[i].occupied {
		if m.entries[i].key == key {
			m.entries[i].value = value
			return
		}
		i = (i + 1) & mask
	}
	if m.count + 1 > len(m.entries) - len(m.entries) / 4 {
		int_map_grow(m)
		mask = len(m.entries) - 1
		i = int(int_map_hash(key) & u64(mask))
		for m.entries[i].occupied {i = (i + 1) & mask}
	}
	m.entries[i] = IntMapEntry{key, value, true}
	m.count += 1
}

@(private)
int_map_delete :: proc(m: ^IntMap, key: int) {
	if m.count == 0 {return}
	mask := len(m.entries) - 1
	hole := int(int_map_hash(key) & u64(mask))
	for m.entries[hole].occupied {
		if m.entries[hole].key == key {break}
		hole = (hole + 1) & mask
	}
	if !m.entries[hole].occupied {return}
	m.count -= 1
	// Move a later entry only when its probe path crosses the vacant slot.
	for next := (hole + 1) & mask; m.entries[next].occupied; next = (next + 1) & mask {
		home := int(int_map_hash(m.entries[next].key) & u64(mask))
		if ((hole - home) & mask) < ((next - home) & mask) {
			m.entries[hole] = m.entries[next]
			hole = next
		}
	}
	m.entries[hole] = IntMapEntry{}
}
