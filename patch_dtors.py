#!/usr/bin/env python3
"""Neutralize .Lregister_call_dtors in a wasm module.

aws-lc's C code registers a process-exit destructor via __cxa_atexit, which
clang lowers into `.Lregister_call_dtors` (a function using block/br_if).
wasm-bindgen 0.2.100 runs __wasm_call_ctors inside its descriptor
interpreter, and that interpreter has no support for block/br_if, so the
bindgen step panics.

Exit-time dtor registration is meaningless in a browser page (there is no
exit), and our __cxa_atexit is a stub, so the body is replaced with an empty
one: the function keeps its signature and name but becomes `end`.

Usage: patch_dtors.py <in.wasm> <out.wasm> [func_name]
"""

import sys

STRUCTURAL = ".Lregister_call_dtors"


def leb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_leb(buf: bytes, i: int) -> tuple[int, int]:
    r = 0
    s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, i
        s += 7


def sections(data: bytes):
    i = 8
    while i < len(data):
        sid = data[i]
        i += 1
        size, i = read_leb(data, i)
        yield sid, data[i : i + size], i, size
        i += size


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    target_name = sys.argv[3] if len(sys.argv) > 3 else STRUCTURAL
    data = open(src, "rb").read()

    num_imported_funcs = 0
    func_idx = None
    for sid, payload, _, _ in sections(data):
        if sid == 2:  # import
            j = 0
            n, j = read_leb(payload, j)
            for _ in range(n):
                ml, j = read_leb(payload, j)
                j += ml
                fl, j = read_leb(payload, j)
                j += fl
                kind = payload[j]
                j += 1
                if kind == 0:
                    _, j = read_leb(payload, j)
                    num_imported_funcs += 1
                elif kind == 1:
                    j += 1
                    flag = payload[j]
                    j += 1
                    _, j = read_leb(payload, j)
                    if flag:
                        _, j = read_leb(payload, j)
                elif kind == 2:
                    flag = payload[j]
                    j += 1
                    _, j = read_leb(payload, j)
                    if flag:
                        _, j = read_leb(payload, j)
                elif kind == 3:
                    j += 2
                elif kind == 4:
                    j += 1
                    _, j = read_leb(payload, j)
        elif sid == 0:  # custom: look for the name section
            j = 0
            nl, j = read_leb(payload, j)
            name = payload[j : j + nl].decode(errors="replace")
            if name != "name":
                continue
            j += nl
            while j < len(payload):
                sub_id = payload[j]
                j += 1
                sub_size, j = read_leb(payload, j)
                sub = payload[j : j + sub_size]
                j += sub_size
                if sub_id != 1:  # 1 = function names
                    continue
                k = 0
                cnt, k = read_leb(sub, k)
                for _ in range(cnt):
                    fi, k = read_leb(sub, k)
                    nl2, k = read_leb(sub, k)
                    fn = sub[k : k + nl2].decode(errors="replace")
                    k += nl2
                    if fn == target_name:
                        func_idx = fi
    if func_idx is None:
        print(f"function {target_name} not found; nothing to do")
        open(dst, "wb").write(data)
        return

    code_entry = func_idx - num_imported_funcs
    if code_entry < 0:
        sys.exit(f"{target_name} is an import, cannot patch")

    out = bytearray(data[:8])
    patched = False
    for sid, payload, _, _ in sections(data):
        if sid == 10 and not patched:  # code
            j = 0
            n, j = read_leb(payload, j)
            entries = []
            hit = -1
            for k in range(n):
                sz, j2 = read_leb(payload, j)
                body = payload[j2 : j2 + sz]
                entries.append(body)
                if k == code_entry:
                    hit = k
                j = j2 + sz
            if hit < 0:
                sys.exit("code entry out of range")
            removed = len(entries[hit]) - 2
            entries[hit] = b"\x00\x0b"  # zero locals, `end`
            new_payload = bytearray(leb(n))
            for b in entries:
                new_payload += leb(len(b)) + b
            out.append(10)
            out += leb(len(new_payload))
            out += new_payload
            patched = True
            print(
                f"patched func #{func_idx} ({target_name}): "
                f"{removed} body bytes removed"
            )
        else:
            out.append(sid)
            out += leb(len(payload))
            out += payload
    if not patched:
        sys.exit("no code section found")
    open(dst, "wb").write(bytes(out))


if __name__ == "__main__":
    main()
