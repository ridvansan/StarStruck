# ES Crypto State (Step 2)

## Reference binary

IOS ES `03/03/10` (`/shared1/00000047.app` on the test NAND) is an ELF32 BE ARM
linked at `0x20100000` and matches every function address in
`modules/es/ES_REIMPLEMENTATION_PLAN.md`. Ghidra project `StarStruckRE`
(language `ARM:BE:32:v5t`); decompiled output in
`~/starstruck-emu/decompiled/es-crypto.txt` (local, not in the repo).

## Module-local syscall stub table

The ES module has its own ARM syscall stubs at `0x2010b0f8 + n*8`; Thumb
thunks (`bx pc; nop` + ARM `b`) jump into them.

| Thunk | Syscall | Name |
|-------|---------|------|
| 0x2010b744 | 0x18 | AllocateOnHeap(0, size) |
| 0x2010b804 | 0x19 | MallocateOnHeap(0, size, align) |
| 0x2010b764 | 0x1A | FreeOnHeap(0, ptr) |
| 0x2010b7ec | 0x5B | IOSC_CreateObject |
| 0x2010b814 | 0x5C | IOSC_DeleteObject |
| 0x2010b7f4 | 0x5F | IOSC_ImportPublicKey |
| 0x2010b7f8 | 0x61 | IOSC_ComputeSharedKey |
| 0x2010b418 | 0x62 | IOSC_SetData (direct stub) |
| 0x2010b820 | 0x67 | IOSC_GenerateHash |
| 0x2010b828 | 0x69 | IOSC_Encrypt |
| 0x2010b80c | 0x6B | IOSC_Decrypt |
| 0x2010b860 | 0x6C | IOSC_VerifyPublicKeySign |
| 0x2010b858 | 0x6F | IOSC_ImportCertificate |
| 0x2010b488 | 0x70 | IOSC_GetDeviceCertificate |
| 0x2010b850 | 0x72 | IOSC_GetOwnership |
| 0x2010b868 | 0x74 | IOSC_GenerateKey |
| 0x2010b878 | 0x75 | IOSC_GeneratePublicKeySign |
| 0x2010b870 | 0x76 | IOSC_GenerateCertificate |

## Implemented so far (branch `feature/es-crypto`)

- `CheckKeyslotPermissions(uid, keyHandle)`
- `Encrypt` / `Decrypt` (ioctlv 0x2c / 0x2d)
- Thin wrappers: `IOSCSetData`, `IOSCEncrypt`, `IOSCGetDeviceCertificate`
- `CertificateSearchFunction` — walks a cert buffer, builds the cert name
  (`"%s"` or `"%s-%s"` with issuer) and matches, including the "AP" prefix
  shortcut. Types: RSA4096 (CA, 0x400), RSA2048 (0x300 RSA / 0x240 ECC),
  ECDSA (0x180). Errors: -1005 bad key type, -1012 unsupported container,
  -1027 not found.
- `UpdateCertificateStore` — reads `/sys/cert.sys`, searches for the cert and
  appends + rewrites the file with `CreateAndWriteFile` when missing.
- Certificate/type definitions added to `modules/es/source/types.h`
  (`SignatureType`, `SignatureRSA2048/4096`, `SignatureECDSA`,
  `CertificateHeader`, `SignerCert`, `SignerCertEcc`, `CACert`, `ECCCert`,
  `Certificate` union).
- `ActiveTitleContext` skeleton (Title at +0x1DC) and `g_ActiveTitleContext`

Verified with the matching loop (`~/starstruck-emu/matching/run-matching.sh`):
call sequences match the original for the crypto wrappers, and the cert
search/store functions follow the decompiled control flow (sizes differ due
to the newer compiler; formatting helpers differ: strlcpy/strlcat vs sprintf).

## Decompiled behavior notes

### CheckKeyslotPermissions (0x2010651c)
```
ret = IOSC_GetOwnership(keyHandle, &ownership)      // 0x72
if ret == 0:
    active = g_ActiveTitleContext
    if active:
        GetTitleUserId(active->Title.Type, active->Title.Id, &titleUid)
        if titleUid == uid: uid = 0xf              // active title users count as 0xf
    if ((1 << (uid & 0xff)) & ownership) == 0 and keyHandle != 6:
        ret = ES_EACCES
```
Key handle 6 is the device key and is always allowed.

### Encrypt (0x20106574) / Decrypt (0x201065b0)
```
if (iv && input && output) {
    if (CheckKeyslotPermissions(uid, keyHandle) == 0)
        return IOSC_Encrypt(keyHandle, iv, input, size, output)   // 0x69 / 0x6B
}
return ES_EINVAL
```

### CertificateSearchFunction (0x201068f4)
Walks a certificate buffer by container type:
- CA: issuer at +0x90, key at +0xa1, size 0x400
- signer: issuer at +0x20, key at +0x31, size 0x180
- v1 container: +0x50/+0x61 size 0x300; v2: +0x60/+0x61 size 0x240
Outputs cert pointer, issuer pointer and size; compares issuer name with memcmp.

### UpdateCertificateStore (0x20106a58)
Opens `/sys/cert.sys`, searches for the cert (CertificateSearchFunction); if not
present appends it and rewrites the file with `CreateAndWriteFile(path, 0, 3, 3,
1, buf, size)`.

### VerifyContainer (0x20106b9c)
CertificateSearch x2 (signer + CA), expected CA issuer name depends on the
container type (param 0/1/2), then `IOSC_ImportCertificate` (0x6F) chains into
IOSC objects and a hash/verify pass.

### Sign (0x20106dd4, ioctlv 0x30)
- requires `(hash & 0x3f) == 0`, sigOut and certOut non-null, active title
- `IOSC_CreateObject(&handle, 0, 4)` → `IOSC_GenerateKey(handle)` (0x74)
- cert name = `"%s-%08x%08x"` from active title fields (+0x18c/+0x190)
- `IOSC_GenerateCertificate(handle, name, certOut)` (0x76)
- `IOSC_GenerateHash(ctx, hash, len, 2, digest)` (0x67)
- `IOSC_GeneratePublicKeySign(digest, 0x14, handle, sigOut)` (0x75)
- `IOSC_DeleteObject(handle)`

### VerifySign (0x20106f08, ioctlv 0x31)
CertificateSearch + VerifyContainer, then `IOSC_ImportPublicKey` (0x5F),
`IOSC_GenerateHash` (0x67) and `IOSC_VerifyPublicKeySign` (0x6C).

## Still needed

- Kernel: IOSC syscalls 0x6C, 0x6F, 0x70, 0x74, 0x75, 0x76 (table entries are
  still `SYSCALL_NULL`); 0x61 needs ECC point multiplication.
- ES: `VerifyContainer`, `Sign`, `VerifySign`, certificate store, `crypto/`
  struct definitions (`Certificate` family, `ECCCert`, ...).
- Core wrappers for 0x6C/0x6F/0x70/0x74/0x75/0x76 were added in
  `core/include/ios/syscalls.h` + `syscalls_asm.s`.
