/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - shared type definitions.

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#pragma once

#include <types.h>

typedef enum
{
	SystemTitle = 0x00000001, /* IOS, System Menu, BC, MIOS, ... */
	ChannelTitle = 0x00010000, /* Installed via the Shop Channel */
	GameSaveTitle = 0x00010001, /* Disc-based game saves */
	SysChannelTitle = 0x00010002, /* System channels */
	WiiWareTitle = 0x00010004, /* WiiWare / game channels */
	DLCTitle = 0x00010005, /* Downloadable content */
	HiddenTitle = 0x00010008, /* Hidden channels (TOS, etc.) */
} TitleType;

typedef struct
{
	TitleType Type;
	u32 Id;
} TitleID;
CHECK_SIZE(TitleID, 0x08);
CHECK_OFFSET(TitleID, 0x00, Type);
CHECK_OFFSET(TitleID, 0x04, Id);

typedef struct
{
	TitleID Title;
	u32 UserId;
} TitleUIDEntry;
CHECK_SIZE(TitleUIDEntry, 0x0C);
CHECK_OFFSET(TitleUIDEntry, 0x00, Title);
CHECK_OFFSET(TitleUIDEntry, 0x08, UserId);

// Currently-running title state. Only the fields needed by the crypto code
// are modeled so far; the full struct gets filled in during the launch step.
// Removed: redefined after the TMD types below.

typedef enum
{
	RSA4096_SHA1 = 0x10000,
	RSA2048_SHA1 = 0x10001,
	ECDSA_SHA1 = 0x10002,
} SignatureType;

typedef struct
{
	SignatureType Type;
	u8 Signature[256];
	u8 Padding[60];
	char Issuer[64];
} SignatureRSA2048;
CHECK_SIZE(SignatureRSA2048, 0x180);

typedef struct
{
	SignatureType Type;
	u8 Signature[512];
	u8 Padding[60];
	char Issuer[64];
} SignatureRSA4096;
CHECK_SIZE(SignatureRSA4096, 0x280);

typedef struct
{
	SignatureType Type;
	u8 Signature[60];
	u8 Padding[64];
	char Issuer[64];
} SignatureECDSA;
CHECK_SIZE(SignatureECDSA, 0xC0);

// Type is the public key type: 1 = RSA-2048, 2 = ECC-233
typedef struct
{
	u32 Type;
	char Name[64];
	u32 KeyId;
} CertificateHeader;
CHECK_SIZE(CertificateHeader, 0x48);

typedef struct
{
	SignatureRSA2048 Signature;
	CertificateHeader Header;
	u8 PublicKey[256];
	u8 Padding[0x38];
} SignerCert;
CHECK_SIZE(SignerCert, 0x300);

typedef struct
{
	SignatureRSA2048 Signature;
	CertificateHeader Header;
	u8 PublicKey[60];
	u8 Padding[0x3C];
} SignerCertEcc;
CHECK_SIZE(SignerCertEcc, 0x240);

typedef struct
{
	SignatureRSA4096 Signature;
	CertificateHeader Header;
	u8 PublicKey[256];
	u8 Padding[0x38];
} CACert;
CHECK_SIZE(CACert, 0x400);

typedef struct
{
	SignatureECDSA Signature;
	CertificateHeader Header;
	u8 PublicKey[60];
	u8 Padding[60];
} ECCCert;
CHECK_SIZE(ECCCert, 0x180);

typedef union
{
	SignerCert Signer;
	SignerCertEcc SignerEcc;
	CACert Ca;
	ECCCert Ecc;
	u8 Raw[0x400];
} Certificate;
CHECK_SIZE(Certificate, 0x400);

typedef struct
{
	u32 ContentId;
	u16 Index;
	u16 Type;
	u64 Size;
	u8 Sha1Hash[20];
} __attribute__((packed)) TitleMetadataContent;
CHECK_SIZE(TitleMetadataContent, 0x24);

typedef struct
{
	SignatureRSA2048 SignedBlobHeader;  // +0x000
	u8 Version;                         // +0x180
	u8 CaCrlVersion;                    // +0x181
	u8 SignerCrlVersion;                // +0x182
	bool IsVwiiTitle;                   // +0x183
	u64 RequiredSystemVersion;          // +0x184
	u64 TitleId;                        // +0x18c
	u32 TitleType;                      // +0x194
	u16 GroupId;                        // +0x198
	u16 Padding;                        // +0x19a
	u16 Region;                         // +0x19c
	u8 Ratings[16];                     // +0x19e
	u8 Reserved[12];                    // +0x1ae
	u8 IpcMask[12];                     // +0x1ba
	u8 Reserved2[18];                   // +0x1c6
	u32 AccessRights;                   // +0x1d8
	u16 TitleVersion;                   // +0x1dc
	u16 ContentCount;                   // +0x1de
	u16 BootIndex;                      // +0x1e0
	u16 MinorVersion;                   // +0x1e2
	TitleMetadataContent Contents[512]; // +0x1e4
} __attribute__((packed)) TitleMetadata;
CHECK_SIZE(TitleMetadata, 0x1E4 + 512 * 0x24);
CHECK_OFFSET(TitleMetadata, 0x180, Version);
CHECK_OFFSET(TitleMetadata, 0x184, RequiredSystemVersion);
CHECK_OFFSET(TitleMetadata, 0x18c, TitleId);
CHECK_OFFSET(TitleMetadata, 0x194, TitleType);
CHECK_OFFSET(TitleMetadata, 0x198, GroupId);
CHECK_OFFSET(TitleMetadata, 0x19a, Padding);
CHECK_OFFSET(TitleMetadata, 0x1dc, TitleVersion);
CHECK_OFFSET(TitleMetadata, 0x1de, ContentCount);
CHECK_OFFSET(TitleMetadata, 0x1e0, BootIndex);
CHECK_OFFSET(TitleMetadata, 0x1e4, Contents);

typedef struct
{
	u32 ContentId;
	u16 Index;
	u16 Type;
	u64 Size;
} TitleMetadataViewContent;
CHECK_SIZE(TitleMetadataViewContent, 0x10);

typedef struct
{
	u8 Version;                 // +0x00
	u8 Padding[3];
	u64 SystemVersion;          // +0x04
	u64 TitleId;                // +0x0c
	u32 TitleType;              // +0x14
	u16 GroupId;                // +0x18
	u8 Unknown1[62];            // +0x1a
	u16 TitleVersion;           // +0x58
	u16 NumContents;            // +0x5a
	TitleMetadataViewContent Contents[512]; // +0x5c
} __attribute__((packed)) TitleMetadataView;
CHECK_SIZE(TitleMetadataView, 0x5C + 512 * 0x10);
CHECK_OFFSET(TitleMetadataView, 0x00, Version);
CHECK_OFFSET(TitleMetadataView, 0x04, SystemVersion);
CHECK_OFFSET(TitleMetadataView, 0x0c, TitleId);
CHECK_OFFSET(TitleMetadataView, 0x14, TitleType);
CHECK_OFFSET(TitleMetadataView, 0x18, GroupId);
CHECK_OFFSET(TitleMetadataView, 0x1a, Unknown1);
CHECK_OFFSET(TitleMetadataView, 0x58, TitleVersion);
CHECK_OFFSET(TitleMetadataView, 0x5a, NumContents);
CHECK_OFFSET(TitleMetadataView, 0x5c, Contents);

// Currently-running title state.
typedef struct
{
	u32 Unknown;                // +0x00
	TitleMetadata* Tmd;         // +0x04
	u32 IsActive;               // +0x08
	u8 Padding[0x1DC - 0x0C];
	TitleID Title;              // +0x1DC
} ActiveTitleContext;
CHECK_SIZE(ActiveTitleContext, 0x1E4);
CHECK_OFFSET(ActiveTitleContext, 0x04, Tmd);
CHECK_OFFSET(ActiveTitleContext, 0x08, IsActive);
CHECK_OFFSET(ActiveTitleContext, 0x1DC, Title);