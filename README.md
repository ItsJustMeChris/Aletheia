# Aletheia

Aletheia is a macOS proof-of-concept that pairs an encrypted Mach-O executable with a companion watcher dylib.  
The watcher enforces on-demand page decryption: encrypted code pages trigger a `SIGSEGV`, the dylib decrypts just-in-time, lets execution proceed, and then re-encrypts the page when it goes idle. The project is aimed at reverse-engineering and software-protection research demos.

## Project Highlights
- **Self-decrypting payload** – `parent/main.c` keeps its `__TEXT,__text` section XOR-encrypted on disk and decrypts only the pages that are actively executing.
- **Mach exception choreography** – `dylib/watcher.c` installs a `SIGSEGV/SIGBUS` handler, flips page protections with `mach_vm_protect`, and uses `pthread_jit_write_protect_np` on Apple Silicon to satisfy hardened runtime rules.
- **Black-box deploy** – `scripts/encrypt_binary.py` scans Mach-O load commands to locate the text section, encrypts it, updates `maxprot`, and emits a runnable encrypted binary without manual offsets.
- **Auto-build workflow** – `scripts/build.sh` compiles every component, performs segment encryption, applies ad-hoc signatures with JIT entitlements, and drops artifacts in `build/`.

## How It Works
1. **Compile & encrypt** – The build script compiles `parent_binary`, then XORs its text section using `encrypt_binary.py`, yielding `parent_binary_encrypted`. The encryption key defaults to `0x55`.
2. **Arm page protections** – When the encrypted binary launches with `libwatcher.dylib` injected, the dylib identifies the executable image and marks its text pages `PROT_NONE`.
3. **Intercept faults** – Any attempt to execute the encrypted code faults. The handler temporarily grants read/write, XOR-decrypts the page, clears the instruction cache, and restores RX permissions.
4. **Re-hide on idle** – A monitor thread timestamps decrypted pages and re-encrypts any page that has been idle for ~500 ms, restoring `PROT_NONE`.

## Requirements
- macOS 13 or newer (tested on Apple Silicon; x86_64 should work but is not exercised regularly).
- Xcode Command Line Tools providing `clang`, `codesign`, and Mach headers (`xcode-select --install`).
- Python 3.9+ for the encryption utility (uses only the standard library).
- Ability to run ad-hoc signed binaries (System Integrity Protection must remain enabled; no kernel modifications are required).

## Quick Start
Run all commands from the repository root.

```bash
./scripts/build.sh
DYLD_INSERT_LIBRARIES=build/libwatcher.dylib ./build/parent_binary_encrypted
```

Expected runtime log (truncated):

```
[watcher] Watcher dylib loaded.
[watcher] Protected pages armed: 0x8 (8)
SIGSEGV at address: 0x104038000
Decrypting page at 0x104038000
Page decrypted and executable.
Parent process started. Preparing payload...
[driver] Iteration 1 -> stage 2
...
```

To observe the failure mode without the watcher:

```bash
./build/parent_binary_encrypted   # terminates with SIGILL/SIGTRAP because pages stay encrypted
```

## Repository Layout
- `parent/main.c` – long-running payload driver that fabricates data, exercises ten transformation stages, and periodically reports checksums.
- `dylib/watcher.c` – Mach-O introspection, fault handling, page accounting, and background re-encryption logic.
- `scripts/build.sh` – orchestrated build & sign pipeline.
- `scripts/encrypt_binary.py` – Mach-O parser and XOR encryptor; supports custom keys with `--key`.
- `scripts/entitlements.plist` – minimal entitlements granting JIT permissions for hardened macOS processes.
- `build/` – populated after running the build script (ignored by version control).

## Customisation
- **Encryption key** – change with `python3 scripts/encrypt_binary.py --key 0xAA` (remember to rebuild or re-run the script if you skip `build.sh`).
- **Architecture** – `build.sh` compiles for `uname -m`. Override by exporting `ARCH` before running the script, e.g. `ARCH=x86_64 ./scripts/build.sh`.
- **Output paths** – `encrypt_binary.py` takes `--input`/`--output` so you can encrypt other Mach-O binaries produced by the build.

## Verification Tips
- `otool -l build/parent_binary_encrypted | grep -A5 __TEXT` to confirm the `VMSIZE` and `maxprot` adjustments.
- `otool -tV build/parent_binary` vs. `build/parent_binary_encrypted` to compare clear vs. XOR’d instructions.
- `vmmap <pid>` while the demo runs to inspect page protection flips in real time.

## Troubleshooting
- **Architecture mismatch** – Ensure the dylib and binary share the same slice (`file build/*` to inspect). Re-run the build script after forcing `ARCH`.
- **`mach_vm_protect` failures** – Usually indicates SIP-restricted permissions. Rerun the binary from an ad-hoc signed location (the build script handles signing).
- **Silent exits** – Check `Console.app` for crash logs; executing the encrypted payload without the watcher should crash immediately with `EXC_BAD_INSTRUCTION`.
- **Python errors** – Verify that Python can run from `/usr/bin/python3` or `python3` on PATH; no external packages are needed.

## Notes & Ethics
- The encryption routine uses XOR for simplicity; swap in a stronger cipher for realistic protection research.
- The demo touches low-level system APIs—run it only on systems you control and understand.
- All code is intended for educational use in exploring runtime code encryption, not for hiding malicious behaviour.
