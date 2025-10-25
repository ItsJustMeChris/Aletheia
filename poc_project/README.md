# PoC: Dynamic Library for On-the-Fly Page Decryption on macOS

This proof-of-concept demonstrates a dynamic library (dylib) that monitors page accesses for an encrypted parent process, decrypts pages on violation, and re-encrypts them afterward. For software security defense lectures.

## Directory Structure
- `parent/main.c`: Source for the parent process.
- `dylib/watcher.c`: Dylib source for monitoring and handling.
- `scripts/encrypt_binary.py`: Python script to encrypt the __TEXT segment.

## Prerequisites
- macOS with Xcode Command Line Tools (`xcode-select --install`).
- Python 3 (built-in on macOS).
- No external libraries needed for this PoC (simple XOR encryption).

## Build and Run Instructions

Run these from the root of this project (`poc_project/` directory).

### Quick build
```bash
cd poc_project
./scripts/build.sh
```
This script compiles the parent binary, encrypts its `__TEXT,__text` section, builds the watcher dylib, and ad-hoc signs both artifacts. The signing step applies the `com.apple.security.cs.allow-jit` entitlement so the watcher can temporarily write to executable memory on modern macOS.

### Manual steps (optional)

1. `clang parent/main.c -Wl,-segprot,__TEXT,rwx,r-x -o build/parent_binary`
2. `python3 scripts/encrypt_binary.py`
3. `clang -dynamiclib -o build/libwatcher.dylib dylib/watcher.c -arch $(uname -m)`
4. `codesign -f -s - --timestamp=none --entitlements scripts/entitlements.plist build/parent_binary`  
   `codesign -f -s - --timestamp=none --entitlements scripts/entitlements.plist build/parent_binary_encrypted`  
   `codesign -f -s - build/libwatcher.dylib`

### Execute the PoC
```bash
DYLD_INSERT_LIBRARIES=build/libwatcher.dylib ./build/parent_binary_encrypted
```

## Expected Output
```
Watcher dylib loaded.
Protected pages set up.
Parent process started.
SIGSEGV at address: 0x100000xxx
Decrypting page at 0x100000000
Page decrypted and executable.
This is a secret function, decrypted and running!
Re-encrypting page at 0x100000000
Parent process exiting.
```

## Testing Security
- **Without dylib**: `./build/parent_binary_encrypted` should crash (invalid instructions due to encryption).
- **With dylib**: Should run successfully, printing the secret function.
- **Analysis Resistance**: Use `otool -t build/parent_binary_encrypted` to see encrypted (gibberish) text. Memory is protected (`PROT_NONE`) until accessed.

## Troubleshooting
- **Architecture mismatch**: Ensure `-arch $(uname -m)` matches your system (run `uname -m` to check).
- **Permission errors**: Disable SIP temporarily if needed (`csrutil disable` in Recovery Mode, reboot). Re-enable after testing.
- **mprotect failures**: Virtual addresses in `watcher.c` must match the binary's loaded address (use `otool -lV` for VM addresses).
- **Signal issues**: `sleep(1)` is PoC-only; real impl needs async-safe re-encryption.
- **macOS Version**: Tested concepts on macOS 14+; older versions may vary with Mach APIs.

## Notes and Limitations
- Encryption is simple XOR for demo; replace with AES for strength.
- Pages re-encrypt after 1s delay—enhance with execution hooks.
- For lecture: Discuss mprotect/SIGSEGV mechanics, anti-RE benefits, and real-world challenges (e.g., key management).

See the original guide for enhancements, talking points, and further reading.
