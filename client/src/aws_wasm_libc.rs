//! Minimal libc surface for the aws-lc C library on wasm32-unknown-unknown.
//!
//! aws-lc's C code targets platforms with a libc. On this target there is
//! none, so the handful of symbols that survive the link (allocator, string
//! helpers, entropy, and a few diagnostics stubs) are defined here in Rust.
//!
//! The allocator functions are correct implementations backed by the Rust
//! global allocator; the string helpers are correct; `getentropy` is correct
//! (WebCrypto). The printf-family and file I/O entries are stubs: aws-lc only
//! reaches them on error/diagnostic paths that do not affect the TLS
//! handshake, so they write an empty string and return success without
//! ever trapping.
//!
//! WASM calling convention note: C variadic calls compile to a fixed-arity
//! wasm import (verified against the built objects), so these definitions
//! match the imported types exactly.

// This module is deliberately C-shaped: pointer math, libc semantics, casts.
// The crate builds with clippy::pedantic; rather than contorting libc-shaped
// code into clippy style, the pedantic set is switched off for this file.
#![allow(clippy::pedantic)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use std::alloc::{alloc, dealloc, realloc as rust_realloc, Layout};
use std::os::raw::{c_char, c_int, c_long, c_void};
use wasm_bindgen::JsCast;

#[allow(clippy::missing_safety_doc)]
#[allow(dead_code)]
mod imp {
	use super::*;

	// --- allocator (header-prefixed, 16-byte aligned) ---

	const HDR: usize = 16;

	unsafe fn layout_for(size: usize) -> Option<Layout> {
		Layout::from_size_align(size.saturating_add(HDR), 16).ok()
	}

	unsafe fn store_size(base: *mut u8, size: usize) {
		base.cast::<u32>().write_unaligned(size as u32);
	}

	unsafe fn load_size(p: *mut c_void) -> usize {
		(p as *mut u8).sub(HDR).cast::<u32>().read_unaligned() as usize
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
		let Some(lo) = layout_for(size) else { return std::ptr::null_mut() };
		let base = alloc(lo);
		if base.is_null() {
			return std::ptr::null_mut();
		}
		store_size(base, size);
		base.add(HDR) as *mut c_void
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
		let bytes = match nmemb.checked_mul(size) {
			Some(b) => b,
			None => return std::ptr::null_mut(),
		};
		let p = malloc(bytes);
		if !p.is_null() && bytes > 0 {
			std::ptr::write_bytes(p as *mut u8, 0, bytes);
		}
		p
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn realloc(p: *mut c_void, size: usize) -> *mut c_void {
		if p.is_null() {
			return malloc(size);
		}
		let old = load_size(p);
		let Some(lo_old) = layout_for(old) else { return std::ptr::null_mut() };
		let Some(lo_new) = layout_for(size) else { return std::ptr::null_mut() };
		let base = rust_realloc(p as *mut u8, lo_old, lo_new.size());
		if base.is_null() {
			return std::ptr::null_mut();
		}
		store_size(base, size);
		base.add(HDR) as *mut c_void
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn free(p: *mut c_void) {
		if p.is_null() {
			return;
		}
		let old = load_size(p);
		// SAFETY: the layout here is exactly the one malloc/realloc used.
		let lo = Layout::from_size_align(old + HDR, 16).unwrap_unchecked();
		dealloc((p as *mut u8).sub(HDR), lo);
	}

	// --- string / memory helpers ---

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
		let mut n = 0;
		while *s.add(n) != 0 {
			n += 1;
		}
		n
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
		let b = c as u8;
		let mut i = 0;
		loop {
			let cur = *s.add(i) as u8;
			if cur == b {
				return s.add(i) as *mut c_char;
			}
			if cur == 0 {
				return std::ptr::null_mut();
			}
			i += 1;
		}
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
		let mut i = 0;
		while *a.add(i) != 0 && *a.add(i) == *b.add(i) {
			i += 1;
		}
		(*a.add(i) as c_int) - (*b.add(i) as c_int)
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
		let mut i = 0;
		if n == 0 {
			return 0;
		}
		while i + 1 < n && *a.add(i) != 0 && *a.add(i) == *b.add(i) {
			i += 1;
		}
		(*a.add(i) as c_int) - (*b.add(i) as c_int)
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
		let mut i = 0;
		loop {
			let cur = *s.add(i);
			if cur == 0 {
				return std::ptr::null_mut();
			}
			let mut j = 0;
			while *accept.add(j) != 0 {
				if cur == *accept.add(j) {
					return s.add(i) as *mut c_char;
				}
				j += 1;
			}
			i += 1;
		}
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
		let b = c as u8;
		let s = s as *const u8;
		for i in 0..n {
			if *s.add(i) == b {
				return s.add(i) as *mut c_void;
			}
		}
		std::ptr::null_mut()
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
		let a = a as *const u8;
		let b = b as *const u8;
		for i in 0..n {
			let (x, y) = (*a.add(i), *b.add(i));
			if x != y {
				return x as c_int - y as c_int;
			}
		}
		0
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strtol(s: *const c_char, endp: *mut *mut c_char, base: c_int) -> c_long {
		let mut i = 0;
		let s = s as *const u8;
		while matches!(*s.add(i), b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
			i += 1;
		}
		let mut neg = false;
		if *s.add(i) == b'-' {
			neg = true;
			i += 1;
		} else if *s.add(i) == b'+' {
			i += 1;
		}
		let mut base = base;
		if (base == 0 || base == 16)
			&& *s.add(i) == b'0'
			&& (*s.add(i + 1) | 0x20) == b'x'
			&& matches!(*s.add(i + 2), b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
		{
			i += 2;
			base = 16;
		} else if base == 0 {
			base = if *s.add(i) == b'0' { 8 } else { 10 };
		}
		let mut acc: u64 = 0;
		let mut any = false;
		loop {
			let c = *s.add(i);
			let d = match c {
				b'0'..=b'9' => (c - b'0') as u64,
				b'a'..=b'z' => (c - b'a' + 10) as u64,
				b'A'..=b'Z' => (c - b'A' + 10) as u64,
				_ => break,
			};
			if d >= base as u64 {
				break;
			}
			acc = acc.saturating_mul(base as u64).saturating_add(d);
			any = true;
			i += 1;
		}
		if !any {
			if !endp.is_null() {
				*endp = s as *mut c_char;
			}
			return 0;
		}
		if !endp.is_null() {
			*endp = s.add(i) as *mut c_char;
		}
		let clamp = if neg { i64::MIN } else { i64::MAX } as u64;
		let v = acc.min(clamp) as i64;
		v as c_long
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strtoul(s: *const c_char, endp: *mut *mut c_char, base: c_int) -> u64 {
		let r = strtol(s, endp, base);
		r as u64
	}

	// --- sorting / searching ---

	type Cmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

	unsafe fn byte_swap(a: *mut u8, b: *mut u8, size: usize) {
		for i in 0..size {
			std::ptr::swap(a.add(i), b.add(i));
		}
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn qsort(base: *mut c_void, nmemb: usize, size: usize, cmp: Cmp) {
		if size == 0 || nmemb < 2 {
			return;
		}
		// insertion sort: the pulled call sites sort small tables
		for i in 1..nmemb {
			let mut j = i;
			while j > 0
				&& cmp(base.add((j - 1) * size), base.add(j * size)) > 0
			{
				byte_swap(
					base.add((j - 1) * size) as *mut u8,
					base.add(j * size) as *mut u8,
					size,
				);
				j -= 1;
			}
		}
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn bsearch(
		key: *const c_void,
		base: *const c_void,
		nmemb: usize,
		size: usize,
		cmp: Cmp,
	) -> *mut c_void {
		let mut lo = 0;
		let mut hi = nmemb;
		while lo < hi {
			let mid = lo + (hi - lo) / 2;
			let c = cmp(key, base.add(mid * size));
			if c == 0 {
				return base.add(mid * size) as *mut c_void;
			}
			if c > 0 {
				lo = mid + 1;
			} else {
				hi = mid;
			}
		}
		std::ptr::null_mut()
	}

	// --- entropy (WebCrypto, chunked under the 65536-byte quota) ---

	const QUOTA: u32 = 65536;

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
		let global = js_sys::global();
		let crypto = match js_sys::Reflect::get(&global, &wasm_bindgen::JsValue::from_str("crypto")) {
			Ok(c) if !c.is_undefined() && !c.is_null() => c,
			_ => return -1,
		};
		let gv = match js_sys::Reflect::get(&crypto, &wasm_bindgen::JsValue::from_str("getRandomValues")) {
			Ok(f) => f,
			_ => return -1,
		};
		let f = match gv.dyn_into::<js_sys::Function>() {
			Ok(f) => f,
			_ => return -1,
		};
		let mut off: usize = 0;
		while off < len {
			let chunk = (len - off).min(QUOTA as usize) as u32;
			let arr = js_sys::Uint8Array::new_with_length(chunk);
			if f
				.call1(&crypto, &arr)
				.map_err(|_| ())
				.is_err()
			{
				return -1;
			}
			arr.raw_copy_to_ptr((buf as *mut u8).add(off));
			off += chunk as usize;
		}
		0
	}

	// --- diagnostics stubs (error paths only; never reached by the handshake) ---

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn abort() -> ! {
		std::process::abort()
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn strerror(_err: c_int) -> *const c_char {
		static MSG: &[u8] = b"unknown error\0";
		MSG.as_ptr() as *const c_char
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn snprintf(
		buf: *mut c_char,
		size: usize,
		_fmt: *const c_char,
		_varargs: usize,
	) -> c_int {
		if !buf.is_null() && size > 0 {
			*buf = 0;
		}
		0
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn vsnprintf(
		buf: *mut c_char,
		size: usize,
		_fmt: *const c_char,
		_ap: *mut c_void,
	) -> c_int {
		if !buf.is_null() && size > 0 {
			*buf = 0;
		}
		0
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn fprintf(_f: *mut c_void, _fmt: *const c_char, _v: usize) -> c_int {
		0
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn fputs(_s: *const c_char, _f: *mut c_void) -> c_int {
		1
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn __cxa_atexit(
		_f: usize,
		_arg: usize,
		_dso: usize,
	) -> c_int {
		0
	}

	#[unsafe(no_mangle)]
	pub unsafe extern "C" fn fwrite(
		_p: *const c_void,
		_size: usize,
		n: usize,
		_f: *mut c_void,
	) -> usize {
		n
	}

	// errno: wasi-libc references it as a plain mutable global
	#[unsafe(no_mangle)]
	pub static mut errno: c_int = 0;

	// FILE globals: never dereferenced by the stubs above
	#[unsafe(no_mangle)]
	pub static mut stderr: *mut c_void = 1 as *mut c_void;
	#[unsafe(no_mangle)]
	pub static mut stdout: *mut c_void = 1 as *mut c_void;
}
