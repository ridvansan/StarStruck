# ES TMD State (Step 4)

Reference: IOS ES 03/03/10 (`/shared1/00000047.app`), decompilation in
`~/starstruck-emu/decompiled/es-tmd.txt`.

## Implemented (branch `feature/es-crypto`)

| Function | Status | Verified |
|----------|--------|----------|
| `GetStoredTmd` (0x2010710c) | done | same calls, different cleanup order |
| `GenerateTMDView` (0x201071f0) | done | calls 80% (packed-struct code differs) |
| `GetTitleMetadataView` (0x2010738c) | done | calls 70% |
| `GetActiveTitleTMD` (0x2010733c) | done | calls 100% |
| `WriteTempTmd` (0x2010311c) | done | calls 100% |

Key paths/formats:
- TMD: `"%s/%08x/%08x/content/title.tmd"` with prefix `"/title"`
- content: `"%s/%08x/%08x/content/%08x.app"` with prefix `"/title"`
- temp TMD: `/tmp/title.tmd`

Types (in `modules/es/source/types.h`): `TitleMetadataContent` (0x24, packed),
`TitleMetadata` (0x1e4 + ContentCount*0x24, packed), `TitleMetadataViewContent`
(0x10), `TitleMetadataView` (0x5c + ContentCount*0x10, packed).

`ActiveTitleContext` now models `+0x04 = TitleMetadata* Tmd` and
`+0x08 = IsActive` (used by GenerateTMDView/GetActiveTitleTMD).

## Remaining Step 4 functions

- `GetStoredTMDContentsInner` (0x20108030) — iterates the TMD contents; for
  shared contents (type signed negative, i.e. 0x8001/0x8004) calls
  `GetSharedContent` (0x20104e04), otherwise opens the `.app` path and
  records the content id. Output is a count (u32* == NULL path) or an array
  of content ids.
- `GetTitleContents` (0x2010819c) — stored TMD + `GetStoredTMDContentsInner`.
- `GetStoredTMDContents` (0x20108280) — in-memory TMD + `VerifyContainer`
  (needs ECC) + `GetStoredTMDContentsInner`.
- `WriteTMDForNewTitle` (0x20105aa8) / `CheckTitleVersionsAndStuff`
  (0x20102c10) — install-path helpers.

**Blocker for the contents functions**: `GetSharedContent` (0x20104e04)
scans `/shared1/content.map` (records of 0x1c: cid + SHA1 + padding) and
uses two helpers that still need identification:
- `FUN_20109148` — hex string -> value (declared `hextou32` in the plan)
- `FUN_2010ad50` — formats the shared content name/path
- error -0x6a (-106) when a hash is not found.

Also needed: `GetSharedContents` (0x2010836c) for the list ioctl.
