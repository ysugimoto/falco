//go:build wasip1 && wasm

package main

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"
)

// TestAlignAllocAlignsAbsoluteAddress guards the alignment contract: the
// returned pointer must be aligned even when the arena base is misaligned.
func TestAlignAllocAlignsAbsoluteAddress(t *testing.T) {
	for _, base := range []uintptr{0, 1, 2, 3, 5, 7, 9, 13, 4096 + 1} {
		for _, align := range []uint32{1, 2, 4, 8, 16} {
			ptr, _, ok := alignAlloc(base, 0, 8, align)
			if !ok {
				t.Fatalf("base=%d align=%d: unexpected !ok", base, align)
			}
			if uintptr(ptr)%uintptr(align) != 0 {
				t.Fatalf("base=%d align=%d: ptr=%d not aligned", base, align, ptr)
			}
			if uintptr(ptr) < base {
				t.Fatalf("base=%d align=%d: ptr=%d below base", base, align, ptr)
			}
		}
	}
}

// TestAlignAllocBumpsOffset checks the new offset accounts for both alignment
// padding and size, so successive allocations do not overlap.
func TestAlignAllocBumpsOffset(t *testing.T) {
	// base 8-aligned; align=8 at off=1 must skip to off=8, new offset 8+size.
	ptr, newOff, ok := alignAlloc(0, 1, 4, 8)
	if !ok {
		t.Fatal("unexpected !ok")
	}
	if ptr != 8 {
		t.Fatalf("ptr=%d, want 8 (aligned up from off=1)", ptr)
	}
	if newOff != 12 {
		t.Fatalf("newOff=%d, want 12 (8 padding + 4 size)", newOff)
	}
}

// TestResolveResetLatchesFloor verifies the reset semantics: the first call
// latches a floor and never rewinds past it; later calls rewind exactly to it.
func TestResolveResetLatchesFloor(t *testing.T) {
	// First call latches the floor at the current offset.
	floor, off, latched := resolveReset(false, 0, 200_000)
	if !latched {
		t.Fatal("first reset must latch the floor")
	}
	if floor != 200_000 || off != 200_000 {
		t.Fatalf("first reset: floor=%d off=%d, want 200000/200000", floor, off)
	}

	// Later call: a bigger offset must rewind back to the floor, not below it.
	floor, off, latched = resolveReset(latched, floor, 1_200_000)
	if !latched || floor != 200_000 || off != 200_000 {
		t.Fatalf("later reset: floor=%d off=%d latched=%v, want 200000/200000/true", floor, off, latched)
	}

	// The floor must never grow on subsequent calls.
	floor, off, _ = resolveReset(latched, floor, 5_000_000)
	if floor != 200_000 || off != 200_000 {
		t.Fatalf("floor drifted: floor=%d off=%d, want 200000/200000", floor, off)
	}
}

// TestAlignAllocRejectsOverflow confirms an allocation past the arena end fails
// rather than wrapping or returning an out-of-bounds pointer.
func TestAlignAllocRejectsOverflow(t *testing.T) {
	if _, _, ok := alignAlloc(0, arenaSize-2, 4, 1); ok {
		t.Fatal("expected !ok for allocation past arena end")
	}
	// align=0 is normalized to 1 and must not panic.
	if _, _, ok := alignAlloc(0, 0, 1, 0); !ok {
		t.Fatal("expected ok for align=0 (normalized to 1)")
	}
}

// TestAlignAllocRejectsAlignmentOverflow confirms that alignment padding
// pushing past the arena tail is rejected even when the size alone would fit.
func TestAlignAllocRejectsAlignmentOverflow(t *testing.T) {
	if _, _, ok := alignAlloc(0, arenaSize-2, 4, 8); ok {
		t.Fatal("expected !ok when alignment padding overflows the arena tail")
	}
}

// resetArenaState zeroes the bump arena so each (serial) test starts empty.
func resetArenaState() {
	arenaOff, arenaFloor, arenaFloorLatched = 0, 0, false
}

// TestCabiReallocExhaustionReturnsNull pins the trap path: a non-zero
// allocation that does not fit returns 0, which the canonical ABI treats as a trap.
func TestCabiReallocExhaustionReturnsNull(t *testing.T) {
	resetArenaState()
	arenaOff = arenaSize - 2
	if p := cabiRealloc(0, 0, 1, 100); p != 0 {
		t.Fatalf("expected null when arena exhausted, got %d", p)
	}
}

// TestCabiReallocZeroSizeNonNullWhenFull: a zero-size allocation must return a
// non-null, aligned pointer even when the arena is full.
func TestCabiReallocZeroSizeNonNullWhenFull(t *testing.T) {
	resetArenaState()
	arenaOff = arenaSize
	for _, align := range []uint32{1, 4, 16} {
		p := cabiRealloc(0, 0, align, 0)
		if p == 0 {
			t.Fatalf("align=%d: zero-size realloc must never be null even when full", align)
		}
		if uintptr(p)%uintptr(align) != 0 {
			t.Fatalf("align=%d: ptr=%d not aligned", align, p)
		}
	}
}

// TestCabiReallocShrinkCopies exercises the shrink path (newSize < oldSize, so
// only newSize bytes are copied).
func TestCabiReallocShrinkCopies(t *testing.T) {
	resetArenaState()
	p := cabiRealloc(0, 0, 1, 8)
	if p == 0 {
		t.Fatal("initial alloc returned null")
	}
	idx := uint32(uintptr(p) - arenaBase())
	copy(arena[idx:idx+8], []byte("abcdefgh"))

	np := cabiRealloc(p, 8, 1, 4)
	if np == 0 {
		t.Fatal("shrink returned null")
	}
	nidx := uint32(uintptr(np) - arenaBase())
	if got := string(arena[nidx : nidx+4]); got != "abcd" {
		t.Fatalf("shrink did not copy the first newSize bytes: got %q, want \"abcd\"", got)
	}
}

// TestCabiReallocForeignPointerDoesNotTrap covers the provenance guard: a grow
// whose old pointer is outside the arena must skip the copy and return a fresh
// block instead of panicking (a panic in cabi_realloc is an unrecoverable trap).
func TestCabiReallocForeignPointerDoesNotTrap(t *testing.T) {
	resetArenaState()
	// A pointer below arenaBase with nonzero oldSize must not panic the copy.
	np := cabiRealloc(1, 16, 1, 8)
	if np == 0 {
		t.Fatal("foreign-pointer grow should still allocate a fresh block")
	}
}

// TestResetArenaPreservesFloor asserts resetArena's global mutation: the first
// reset latches the floor, and a later reset rewinds exactly to it.
func TestResetArenaPreservesFloor(t *testing.T) {
	resetArenaState()
	arenaOff = 80_000 // simulate the adapter State high-water mark
	resetArena()
	if !arenaFloorLatched || arenaFloor != 80_000 || arenaOff != 80_000 {
		t.Fatalf("latch: floor=%d off=%d latched=%v, want 80000/80000/true",
			arenaFloor, arenaOff, arenaFloorLatched)
	}
	arenaOff = 900_000 // simulate a call's lowered inputs
	resetArena()
	if arenaFloor != 80_000 || arenaOff != 80_000 {
		t.Fatalf("rewind: floor=%d off=%d, want 80000/80000", arenaFloor, arenaOff)
	}
}

// TestCabiReallocZeroSizeReturnsAlignedNonNull: even a zero-size allocation must
// return a non-null, suitably-aligned pointer.
func TestCabiReallocZeroSizeReturnsAlignedNonNull(t *testing.T) {
	resetArenaState()
	for _, align := range []uint32{1, 2, 4, 8, 16} {
		p := cabiRealloc(0, 0, align, 0)
		if p == 0 {
			t.Fatalf("align=%d: zero-size realloc returned null", align)
		}
		if uintptr(p)%uintptr(align) != 0 {
			t.Fatalf("align=%d: ptr=%d not aligned", align, p)
		}
	}
}

// TestCabiReallocGrowCopies checks that a grow (fresh block) copies the old
// bytes forward, since there is no in-place extend.
func TestCabiReallocGrowCopies(t *testing.T) {
	resetArenaState()
	p := cabiRealloc(0, 0, 1, 4)
	if p == 0 {
		t.Fatal("initial alloc returned null")
	}
	idx := uint32(uintptr(p) - arenaBase())
	copy(arena[idx:idx+4], []byte("abcd"))

	np := cabiRealloc(p, 4, 1, 8)
	if np == 0 {
		t.Fatal("grow returned null")
	}
	nidx := uint32(uintptr(np) - arenaBase())
	if got := string(arena[nidx : nidx+4]); got != "abcd" {
		t.Fatalf("grow did not preserve old bytes: got %q, want \"abcd\"", got)
	}
}

// TestLowerResultEncoding asserts the result<string,string> encoding: ok/err
// discriminant at byte 0, little-endian length at byte 8, non-null payload
// pointer for non-empty payloads, and a 4-byte-aligned return-area pointer.
func TestLowerResultEncoding(t *testing.T) {
	resetArenaState()

	ret := lowerResult("hello", false)
	if uintptr(ret)%4 != 0 {
		t.Fatalf("retArea base %d not 4-byte aligned", ret)
	}
	if uintptr(ret) != uintptr(unsafe.Pointer(&retArea[0])) {
		t.Fatal("ret must point at retArea base")
	}
	b := retAreaBytes()
	if b[0] != 0 {
		t.Fatalf("ok discriminant = %d, want 0", b[0])
	}
	if got := binary.LittleEndian.Uint32(b[8:]); got != 5 {
		t.Fatalf("payload len = %d, want 5", got)
	}
	if binary.LittleEndian.Uint32(b[4:]) == 0 {
		t.Fatal("payload ptr must be non-zero for a non-empty payload")
	}

	// emit(err) -> err(message): discriminant 1, message length encoded.
	emit("", errors.New("boom"))
	b = retAreaBytes()
	if b[0] != 1 {
		t.Fatalf("err discriminant = %d, want 1", b[0])
	}
	if got := binary.LittleEndian.Uint32(b[8:]); got != 4 {
		t.Fatalf("err message len = %d, want 4", got)
	}

	// emit(ok, empty): discriminant 0, ptr 0, len 0.
	emit("", nil)
	b = retAreaBytes()
	if b[0] != 0 || binary.LittleEndian.Uint32(b[4:]) != 0 || binary.LittleEndian.Uint32(b[8:]) != 0 {
		t.Fatalf("empty ok payload not zeroed: disc=%d ptr=%d len=%d",
			b[0], binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:]))
	}
}
