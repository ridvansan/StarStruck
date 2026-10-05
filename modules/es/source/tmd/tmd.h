/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - title metadata (TMD) storage and views

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#pragma once

#include <types.h>

#include "types.h"

// The currently-running title context (defined in crypto/crypto.c)
extern ActiveTitleContext* g_ActiveTitleContext;

// ioctlv 0x34/0x35: read the stored TMD for a title.
// output == NULL queries the size.
s32 GetStoredTmd(u32 titleType, u32 titleId, void* output, u32* sizeInOut);

// ioctlv 0x19/0x1a: convert a full TMD into the PPC-visible view.
s32 GenerateTMDView(TitleMetadata* tmd, void* output, u32* sizeInOut);

// ioctlv 0x14/0x15: read the stored TMD and return its view.
s32 GetTitleMetadataView(u32 titleType, u32 titleId, void* output, u32* sizeInOut);

// ioctlv 0x39/0x3a: return the active title's TMD. output == NULL queries the size.
s32 GetActiveTitleTMD(void* output, u32* sizeInOut);

// Writes the in-progress TMD to /tmp/title.tmd.
s32 WriteTempTmd(const void* data, u32 size);
