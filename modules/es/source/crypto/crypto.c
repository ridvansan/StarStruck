/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - crypto / PKI helpers

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <ios/errno.h>
#include <ios/syscalls.h>

#include "crypto.h"
#include "filesystem/fs.h"

ActiveTitleContext* g_ActiveTitleContext = NULL;

s32 CheckKeyslotPermissions(u32 uid, u32 keyHandle)
{
	u32 ownership = 0;
	s32 ret = OSIOSCGetOwnership(keyHandle, &ownership);
	if (ret != IPC_SUCCESS)
		return ret;

	ActiveTitleContext* activeTitle = g_ActiveTitleContext;
	if (activeTitle != NULL)
	{
		u32 titleUserId = 0;
		ret = GetTitleUserId(activeTitle->Title.Type, activeTitle->Title.Id, &titleUserId);
		if (ret != IPC_SUCCESS)
			return ret;

		// The active title's user is allowed to use the keyslot
		if (titleUserId == uid)
			uid = 0xf;
	}

	//Key handle 6 is the device key and may always be used
	if (((1 << (uid & 0xff)) & ownership) == 0 && keyHandle != 6)
		ret = ES_EACCES;

	return ret;
}

s32 Encrypt(u32 uid, u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData)
{
	if (ivData == NULL || inputData == NULL || outputData == NULL)
		return ES_EINVAL;

	s32 ret = CheckKeyslotPermissions(uid, keyHandle);
	if (ret != IPC_SUCCESS)
		return ret;

	return OSIOSCEncrypt(keyHandle, ivData, inputData, dataSize, outputData);
}

s32 Decrypt(u32 uid, u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData)
{
	if (ivData == NULL || inputData == NULL || outputData == NULL)
		return ES_EINVAL;

	s32 ret = CheckKeyslotPermissions(uid, keyHandle);
	if (ret != IPC_SUCCESS)
		return ret;

	return OSIOSCDecrypt(keyHandle, ivData, inputData, dataSize, outputData);
}

s32 IOSCSetData(u32 keyHandle, u32 value)
{
	return OSSetIOSCData(keyHandle, value);
}

s32 IOSCEncrypt(u32 keyHandle, void* ivData, const void* inputData, u32 dataSize, void* outputData)
{
	return OSIOSCEncrypt(keyHandle, ivData, inputData, dataSize, outputData);
}

s32 IOSCGetDeviceCertificate(void* certOut)
{
	return OSIOSCGetDeviceCertificate(certOut);
}
