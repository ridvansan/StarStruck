/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - crypto / PKI helpers

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#pragma once

#include <types.h>

#include "types.h"

#define ES_EINVAL -1017
#define ES_EACCES -1026

// The currently-running title, used to map the caller uid to the active title.
extern ActiveTitleContext* g_ActiveTitleContext;

// Checks whether the given uid is allowed to use the given IOSC keyslot.
s32 CheckKeyslotPermissions(u32 uid, u32 keyHandle);

// ioctlv 0x2c / 0x2d: AES-CBC encrypt/decrypt with a caller-specified keyslot.
s32 Encrypt(u32 uid, u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData);
s32 Decrypt(u32 uid, u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData);

// Thin wrappers around the IOSC syscalls, used by the ioctlv handlers.
s32 IOSCSetData(u32 keyHandle, u32 value);
s32 IOSCEncrypt(u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData);
s32 IOSCGetDeviceCertificate(void* certOut);
