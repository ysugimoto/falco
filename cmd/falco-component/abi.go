//go:build wasip1 && wasm

package main

// Hand-written Component Model canonical-ABI glue for the reactor build.
// wit-bindgen-go's generated wrappers don't work under standard Go's
// //go:wasmexport, so strings and result<string, string> are marshaled by hand.
// See docs/wasm-component.md for the design.

import (
	"encoding/binary"
	"time"
	"unsafe"
)

// arenaSize bounds one call's combined string arguments. cabi_realloc serves
// allocations from this static arena (not the Go heap) because the host calls
// it re-entrantly on g0 during _initialize, where a heap allocation would trap.
// Oversized input yields a null allocation, which traps the reactor.
const arenaSize = 16 << 20

var (
	arena    [arenaSize]byte
	arenaOff uint32

	// arenaFloor is the bump offset resetArena rewinds to between calls,
	// preserving allocations below it. arenaFloorLatched tracks whether it's set.
	arenaFloor        uint32
	arenaFloorLatched bool
)

func arenaBase() uintptr { return uintptr(unsafe.Pointer(&arena[0])) }

// init latches the reset floor during _initialize, after forcing the preview1
// adapter to allocate its persistent State (via a clock import) so the floor
// sits above it. Resets then preserve State without pinning any call's input.
func init() {
	_ = time.Now() // force the adapter to allocate its persistent State now
	arenaFloor, arenaOff, arenaFloorLatched = resolveReset(false, 0, arenaOff)
}

func arenaAlloc(size, align uint32) uint32 {
	ptr, newOff, ok := alignAlloc(arenaBase(), arenaOff, size, align)
	if !ok {
		return 0
	}
	arenaOff = newOff
	return ptr
}

// alignAlloc computes one bump allocation, aligning the absolute linear-memory
// address (not just the offset) to satisfy the canonical-ABI alignment
// contract. Pure arithmetic so it is unit-testable (see abi_test.go).
func alignAlloc(base uintptr, off, size, align uint32) (ptr uint32, newOff uint32, ok bool) {
	if align == 0 {
		align = 1
	}
	mask := uintptr(align - 1)
	addr := (base + uintptr(off) + mask) &^ mask
	used := uint64(addr - base)
	if used+uint64(size) > arenaSize {
		return 0, off, false
	}
	return uint32(addr), uint32(used) + size, true
}

//go:wasmexport cabi_realloc
func cabiRealloc(ptr, oldSize, align, newSize uint32) uint32 {
	if newSize == 0 {
		// Canonical ABI requires a non-null, aligned pointer even for a zero-size
		// allocation. Prefer a real in-arena address; fall back when exhausted (the
		// bytes are never dereferenced for a zero-size request).
		if p := arenaAlloc(0, align); p != 0 {
			return p
		}
		if align == 0 {
			return 1
		}
		return align
	}
	// Grow/shrink reallocates into a fresh block; there is no in-place extend.
	np := arenaAlloc(newSize, align)
	if ptr != 0 && oldSize != 0 && np != 0 {
		base := arenaBase()
		p := uintptr(ptr)
		n := oldSize
		if newSize < n {
			n = newSize
		}
		// Validate provenance before copying: a foreign/out-of-arena ptr would
		// panic the copy, and a panic in cabi_realloc is an unrecoverable trap. On
		// a bad ptr, skip the copy and return the fresh block.
		if p >= base && p-base <= uintptr(arenaSize) {
			oldIdx := uint32(p - base)
			if uint64(oldIdx)+uint64(n) <= arenaSize {
				newIdx := uint32(uintptr(np) - base)
				copy(arena[newIdx:newIdx+n], arena[oldIdx:oldIdx+n])
			}
		}
	}
	return np
}

// resolveReset computes the post-call bump state: latch the floor on first call,
// then rewind to it thereafter. Pure function, unit-testable (see abi_test.go).
func resolveReset(latched bool, floor, off uint32) (newFloor, newOff uint32, newLatched bool) {
	if !latched {
		return off, off, true
	}
	return floor, floor, true
}

// resetArena rewinds the bump pointer after each export (see resolveReset).
func resetArena() {
	arenaFloor, arenaOff, arenaFloorLatched = resolveReset(arenaFloorLatched, arenaFloor, arenaOff)
}

// liftString views a guest-memory (ptr, len) pair as a Go string without
// copying. The view is valid only for the call duration (resetArena overwrites
// it afterwards), so do not cache or return a value aliasing this memory.
func liftString(ptr, length uint32) string {
	if length == 0 {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), int(length))
}

// retArea is the return area for `result<string, string>`. Backed by [3]uint32
// to force the 4-byte alignment the canonical ABI requires; a single static
// buffer suffices because the host reads it synchronously before the next call.
var retArea [3]uint32

// retAreaBytes views the return area as a 12-byte slice laid out per the
// canonical ABI:
//
//	[0]      discriminant (0 = ok, 1 = err)
//	[4..8)   payload string pointer (i32, little-endian)
//	[8..12)  payload string length  (i32, little-endian)
func retAreaBytes() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&retArea[0])), 12)
}

// retString pins the payload's backing bytes so they stay alive (and at a fixed
// address, since Go's collector is non-moving) while the host lifts them.
var retString string

func lowerResult(payload string, isErr bool) uint32 {
	retString = payload
	b := retAreaBytes()
	if isErr {
		b[0] = 1
	} else {
		b[0] = 0
	}
	var ptr uint32
	if retString != "" {
		ptr = uint32(uintptr(unsafe.Pointer(unsafe.StringData(retString))))
	}
	binary.LittleEndian.PutUint32(b[4:], ptr)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(retString)))
	return uint32(uintptr(unsafe.Pointer(&retArea[0])))
}

// emit lowers a (payload, error) pair: err -> err(message), else ok(payload).
func emit(payload string, err error) uint32 {
	if err != nil {
		return lowerResult(err.Error(), true)
	}
	return lowerResult(payload, false)
}

//go:wasmexport lint
func exportLint(srcPtr, srcLen, optPtr, optLen uint32) uint32 {
	out, err := doLint(liftString(srcPtr, srcLen), liftString(optPtr, optLen))
	ret := emit(out, err)
	resetArena()
	return ret
}

//go:wasmexport format
func exportFormat(srcPtr, srcLen, cfgPtr, cfgLen uint32) uint32 {
	out, err := doFormat(liftString(srcPtr, srcLen), liftString(cfgPtr, cfgLen))
	ret := emit(out, err)
	resetArena()
	return ret
}

//go:wasmexport parse
func exportParse(srcPtr, srcLen uint32) uint32 {
	out, err := doParse(liftString(srcPtr, srcLen))
	ret := emit(out, err)
	resetArena()
	return ret
}

//go:wasmexport tokenize
func exportTokenize(srcPtr, srcLen uint32) uint32 {
	out, err := doTokenize(liftString(srcPtr, srcLen))
	ret := emit(out, err)
	resetArena()
	return ret
}
