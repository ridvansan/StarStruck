/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - crypto / PKI helpers

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <ios/errno.h>
#include <ios/syscalls.h>
#include <fs/fs.h>
#include <string.h>

#include "crypto.h"
#include "filesystem/fs.h"

#define KERNEL_HEAPID 0

ActiveTitleContext* g_ActiveTitleContext = NULL;

static void BuildCertificateSearchName(char* output, u32 outputSize, const CertificateHeader* header,
                                       const char* issuer, bool compareIssuer)
{
	memset(output, 0, outputSize);
	if (!compareIssuer)
	{
		strlcpy(output, header->Name, outputSize);
		return;
	}

	strlcpy(output, issuer, outputSize);
	strlcat(output, "-", outputSize);
	strlcat(output, header->Name, outputSize);
}

s32 CertificateSearchFunction(const char* name, const void* buffer, u32 size, Certificate** certificateOut,
                              u32* entrySizeOut, const char** issuerOut, bool compareIssuer)
{
	const u8* current = (const u8*)buffer;
	const u8* end = current + size;
	s32 result = ES_CERT_NOTFOUND;

	while (current < end)
	{
		SignatureType signatureType = *(const SignatureType*)current;
		const CertificateHeader* header;
		const char* issuer;
		u32 entrySize;

		if (signatureType == RSA2048_SHA1)
		{
			header = &((const SignerCert*)current)->Header;
			issuer = ((const SignerCert*)current)->Signature.Issuer;
			if (header->Type == 1)
				entrySize = sizeof(SignerCert);
			else if (header->Type == 2)
				entrySize = sizeof(SignerCertEcc);
			else
			{
				result = ES_CERT_KEYTYPE;
				break;
			}
		}
		else if (signatureType > RSA2048_SHA1)
		{
			if (signatureType != ECDSA_SHA1)
			{
				result = ES_CERT_CONTAINER;
				break;
			}

			header = &((const ECCCert*)current)->Header;
			issuer = ((const ECCCert*)current)->Signature.Issuer;
			entrySize = sizeof(ECCCert);
		}
		else
		{
			if (signatureType != RSA4096_SHA1)
			{
				result = ES_CERT_CONTAINER;
				break;
			}

			header = &((const CACert*)current)->Header;
			issuer = ((const CACert*)current)->Signature.Issuer;
			entrySize = sizeof(CACert);
		}

		char matchName[0x40];
		BuildCertificateSearchName(matchName, sizeof(matchName), header, issuer, compareIssuer);
		if ((memcmp(name, "AP", 2) == 0 && memcmp(matchName, "AP", 2) == 0) ||
		    memcmp(name, matchName, sizeof(matchName)) == 0)
		{
			*certificateOut = (Certificate*)current;
			*entrySizeOut = entrySize;
			*issuerOut = issuer;
			return IPC_SUCCESS;
		}

		current += entrySize;
		result = ES_CERT_NOTFOUND;
	}

	*certificateOut = NULL;
	*entrySizeOut = 0;
	*issuerOut = NULL;
	return result;
}

s32 UpdateCertificateStore(const char* certificateName, const void* certificate, u32 certificateSize)
{
	FileStatistics* stats = OSAllocateMemory(KERNEL_HEAPID, sizeof(FileStatistics));
	s32 result = ES_ENOMEM;
	u8* fileData = NULL;
	u8* writeBuffer = NULL;
	s32 fd = -1;

	if (stats == NULL)
		return ES_ENOMEM;

	// the original uses the first word of the stats buffer as the file length
	stats->FileLength = 0;
	stats->FilePosition = 0;

	fd = OpenFile(CERT_STORE_PATH, Read);
	if (fd >= 0)
	{
		result = GetFileStats(fd, stats);
		if (result != IPC_SUCCESS)
			goto cleanup;

		fileData = OSAllocateMemory(KERNEL_HEAPID, stats->FileLength);
		if (fileData == NULL)
		{
			result = ES_ENOMEM;
			goto cleanup;
		}

		result = ReadFile(fd, fileData, stats->FileLength);
		if (result != (s32)stats->FileLength)
		{
			result = ES_CERT_READERROR;
			goto cleanup;
		}

		OSCloseFD(fd);
		fd = -1;

		Certificate* foundCertificate = NULL;
		u32 foundEntrySize = 0;
		const char* foundIssuer = NULL;
		result = CertificateSearchFunction(certificateName, fileData, stats->FileLength, &foundCertificate,
		                                   &foundEntrySize, &foundIssuer, false);
		if (foundEntrySize == certificateSize)
			goto cleanup;
	}

	u32 totalSize = certificateSize + stats->FileLength;
	writeBuffer = OSAllocateMemory(KERNEL_HEAPID, totalSize);
	if (writeBuffer == NULL)
	{
		result = ES_ENOMEM;
		goto cleanup;
	}

	if (stats->FileLength == 0)
		memcpy(writeBuffer, certificate, certificateSize);
	else
	{
		memcpy(writeBuffer, fileData, stats->FileLength);
		memcpy(writeBuffer + stats->FileLength, certificate, certificateSize);
	}

	result = CreateAndWriteFile(CERT_STORE_PATH, 0, 3, 3, 1, writeBuffer, totalSize);

cleanup:
	if (fd >= 0)
		OSCloseFD(fd);
	if (writeBuffer != NULL)
		OSFreeMemory(KERNEL_HEAPID, writeBuffer);
	if (fileData != NULL)
		OSFreeMemory(KERNEL_HEAPID, fileData);
	OSFreeMemory(KERNEL_HEAPID, stats);
	return result;
}

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
