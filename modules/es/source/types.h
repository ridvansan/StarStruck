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
typedef struct
{
	u8 Padding[0x1DC];
	TitleID Title;
} ActiveTitleContext;
CHECK_SIZE(ActiveTitleContext, 0x1E4);
CHECK_OFFSET(ActiveTitleContext, 0x1DC, Title);

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