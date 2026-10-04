# IOS Kernel — IOSC syscalls (from decompilation)

## Kernel image / Ghidra setup

The ARM kernel is `/shared1/00000034.app`:

```
0x00  IosKernelHeader (0x10 bytes: HeaderSize, LoaderSize, ElfSize, Arguments)
0x10  loader (0x584 bytes)
0x594 embedded ELF (ElfSize bytes)  -> extracted as ios-kernel.elf
```

The ELF has the same layout as StarStruck's kernel:
- headers/notes at `0x138f0000`
- **crypto/IOSC section at `0x13a70000` (size 0xb488)**
- FS module embedded at `0x20000000`, ES module at `0x20100000`
- kernel code at `0xffff0000`, data at `0xffff87c8`

Ghidra: project `StarStruckRE`, language `ARM:BE:32:v5t`,
`~/ghidra-scripts/DecompileAt.java` (args `T:0x...` / `A:0x...`; removes a
mis-analyzed containing function before creating the real one).

## Syscall dispatch

- Undefined-instruction handler entry: `0xffff1f24` (ARM), SWI handler
  `0xffff1f20`. Vectors at `0xffff0000` point there.
- The handler decodes `(instruction & 0xffffe01f) == 0xE6000010`; syscall
  number = `(instruction >> 5) & 0xFF`; valid for `< 0x7b`.
- **Handler table at `0xffff93d0`** (function pointers, bit0 = Thumb) and
  **stack-arg-count table at `0xffff95b8`** (u32 counts, in words).
- Both tables live in RAM (built during boot), so they are not visible in the
  ELF. Read them from an ironic SRAM dump (`sram0.bin` offset `0x93d0` /
  `0x95b8`) after a chainload run.

### IOSC handler addresses (Kernel 00000034 / IOS80)

| # | Name | Handler (Thumb) |
|---|------|-----------------|
| 0x5B | CreateObject | 0x13a72334 |
| 0x5D | ImportSecretKey | 0x13a725fc |
| 0x5F | ImportPublicKey | 0x13a72964 |
| 0x61 | ComputeSharedKey | 0x13a72bf4 |
| 0x62 | SetData | 0x13a72d98 |
| 0x67 | GenerateHash | 0x13a730f4 |
| 0x69 | Encrypt | 0x13a73394 |
| 0x6B | Decrypt | 0x13a736a4 |
| 0x6C | VerifyPublicKeySign | 0x13a73ad4 |
| 0x6F | ImportCertificate | 0x13a73ef4 |
| 0x70 | GetDeviceCertificate | 0x13a740c0 |
| 0x71 | SetOwnership | 0x13a72484 |
| 0x72 | GetOwnership | 0x13a7254c |
| 0x74 | GenerateKey | 0x13a72b4c |
| 0x75 | GeneratePublicKeySign | 0x13a739cc |
| 0x76 | GenerateCertificate | 0x13a73fe0 |

Inner implementations resolved from the literal pools (all Thumb, mask bit0):

| Inner | Function |
|-------|----------|
| 0x13a70c14 | ImportPublicKey work |
| 0x13a70f0c | GenerateKey work (calls FUN_13a70db8) |
| 0x13a7113c | SetData work (special cases keys 7/8/9/10) |
| 0x13a71484 | VerifyPublicKeySign work |
| 0x13a71490 | GeneratePublicKeySign work |
| 0x13a71668 | ImportCertificate work (cert parse + sign + ImportPublicKey; ECC) |
| 0x13a71ab4 | GenerateCertificate work |
| 0x13a71ac0 | GetDeviceCertificate work |

Shared helpers: `Keyring_GetKeyOwnerProcess` @0x13a71c38,
`Keyring_SetKeyOwnerProcess` @0x13a71be0, `Keyring_FindKeySize` @0x13a7129c,
`CheckMemoryPointer` @0xffff45c8, `IOSC_SwapStack` @0xffff5c9c.

## Real IOSC ownership semantics (decompiled)

`GetOwnership(keyHandle, out)`:
- requires the caller to own the keyslot (root key slot always allowed),
- output buffer must be writable,
- returns `Keyring_GetKeyOwnerProcess(keyHandle, out)`.

`SetOwnership(keyHandle, pidMask)`:
- requires the caller to own the keyslot,
- new owner mask = `existingOwner | (pidMask & 0xfffffff8) | (1 << currentProcessId)`
  - the low 3 bits of `pidMask` are ignored (kernel process ids 0-7),
  - existing owners are preserved.

Implemented on branch `feature/iosc-syscalls`.

## Still TODO (from decompilation)

- `0x74 GenerateKey`: inner 0x13a70f0c -> `FUN_13a70db8` (likely hardware RNG
  + `Keyring_SetKey`).
- `0x62 SetData`: inner 0x13a7113c special-cases key handles 7/8/9/10
  (`DeviceKey`, `NandKey`, `Boot2Key`, ...) and otherwise checks the key type.
- `0x6C` / `0x75` / `0x76` / `0x6F`: all go through ECC-233 math that StarStruck
  does not have yet (the blocker for the remaining crypto syscalls).
- `0x70 GetDeviceCertificate`: inner 0x13a71ac0 still to be analyzed (probably
  reads/generates the device certificate from OTP/seeprom).
