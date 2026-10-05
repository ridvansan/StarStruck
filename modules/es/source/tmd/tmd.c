/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	ES Module - title metadata (TMD) storage and views

	Copyright (C) 2026	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <stdarg.h>
#include <fs/fs.h>
#include <ios/errno.h>
#include <ios/syscalls.h>
#include <string.h>
#include <vsprintf.h>

#include "errors.h"
#include "tmd.h"

#define KERNEL_HEAPID 0

#define TMD_DIRECTORY "/title"
#define TMD_PATH_FORMAT "%s/%08x/%08x/content/title.tmd"
#define TMP_TMD_PATH "/tmp/title.tmd"

static void FormatPath(char* buffer, u32 bufferSize, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, bufferSize, format, args);
	va_end(args);
}

s32 GetStoredTmd(u32 titleType, u32 titleId, void* output, u32* sizeInOut)
{
	char path[0x40];
	FileStatistics* stats = OSAllocateMemory(KERNEL_HEAPID, sizeof(FileStatistics));
	s32 result = ES_ENOMEM;
	s32 fd = -1;

	if (stats == NULL)
		return ES_ENOMEM;

	FormatPath(path, sizeof(path), TMD_PATH_FORMAT, TMD_DIRECTORY, titleType, titleId);

	fd = OpenFile(path, Read);
	if (fd < 0)
	{
		result = fd;
		goto cleanup;
	}

	result = GetFileStats(fd, stats);
	if (result != IPC_SUCCESS)
		goto cleanup;

	if (output == NULL)
	{
		*sizeInOut = stats->FileLength;
		result = IPC_SUCCESS;
	}
	else
	{
		result = ES_EINVAL;
		if (*sizeInOut >= stats->FileLength)
		{
			if ((u32)ReadFile(fd, output, stats->FileLength) == stats->FileLength)
				result = IPC_SUCCESS;
			else
				result = ES_READERROR;
		}
	}

cleanup:
	if (fd >= 0)
		OSCloseFD(fd);
	OSFreeMemory(KERNEL_HEAPID, stats);
	return result;
}

s32 GenerateTMDView(TitleMetadata* tmd, void* output, u32* sizeInOut)
{
	s32 result = ES_EINVAL;
	TitleMetadataView* view = NULL;

	if (tmd == NULL)
	{
		if (g_ActiveTitleContext == NULL || g_ActiveTitleContext->IsActive != 1)
			return ES_EINVAL;

		tmd = g_ActiveTitleContext->Tmd;
	}

	const u32 viewSize = 0x5C + (u32)tmd->ContentCount * 0x10;
	if (output == NULL)
	{
		*sizeInOut = viewSize;
		return IPC_SUCCESS;
	}

	if (*sizeInOut < viewSize)
		return ES_EINVAL;

	view = OSAllocateMemory(KERNEL_HEAPID, viewSize);
	if (view == NULL)
		return ES_ENOMEM;

	memset(view, 0, viewSize);
	view->Version = tmd->Version;
	view->SystemVersion = tmd->RequiredSystemVersion;
	view->TitleId = tmd->TitleId;
	view->TitleType = tmd->TitleType;
	view->GroupId = tmd->GroupId;
	memcpy(view->Unknown1, &tmd->Padding, sizeof(view->Unknown1));
	view->TitleVersion = tmd->TitleVersion;
	view->NumContents = tmd->ContentCount;

	for (u32 i = 0; i < tmd->ContentCount; i++)
	{
		view->Contents[i].ContentId = tmd->Contents[i].ContentId;
		view->Contents[i].Index = tmd->Contents[i].Index;
		view->Contents[i].Type = tmd->Contents[i].Type;
		view->Contents[i].Size = tmd->Contents[i].Size;
	}

	memcpy(output, view, viewSize);
	OSFreeMemory(KERNEL_HEAPID, view);
	return IPC_SUCCESS;
}

s32 GetTitleMetadataView(u32 titleType, u32 titleId, void* output, u32* sizeInOut)
{
	char path[0x40];
	FileStatistics* stats = OSAllocateMemory(KERNEL_HEAPID, sizeof(FileStatistics));
	TitleMetadata* tmd = NULL;
	s32 result = ES_ENOMEM;
	s32 fd = -1;

	if (stats == NULL)
		return ES_ENOMEM;

	FormatPath(path, sizeof(path), TMD_PATH_FORMAT, TMD_DIRECTORY, titleType, titleId);

	fd = OpenFile(path, Read);
	if (fd < 0)
	{
		result = fd;
		goto cleanup;
	}

	result = GetFileStats(fd, stats);
	if (result != IPC_SUCCESS)
		goto cleanup;

	tmd = OSAllocateMemory(KERNEL_HEAPID, stats->FileLength);
	if (tmd == NULL)
	{
		result = ES_ENOMEM;
		goto cleanup;
	}

	if ((u32)ReadFile(fd, tmd, stats->FileLength) != stats->FileLength)
	{
		result = ES_READERROR;
		goto cleanup;
	}

	result = GenerateTMDView(tmd, output, sizeInOut);

cleanup:
	if (fd >= 0)
		OSCloseFD(fd);
	if (tmd != NULL)
		OSFreeMemory(KERNEL_HEAPID, tmd);
	OSFreeMemory(KERNEL_HEAPID, stats);
	return result;
}

s32 GetActiveTitleTMD(void* output, u32* sizeInOut)
{
	s32 result = ES_EINVAL;

	if (g_ActiveTitleContext != NULL && g_ActiveTitleContext->IsActive == 1)
	{
		TitleMetadata* tmd = g_ActiveTitleContext->Tmd;
		const u32 tmdSize = 0x1E4 + (u32)tmd->ContentCount * 0x24;

		if (output == NULL)
		{
			*sizeInOut = tmdSize;
			result = IPC_SUCCESS;
		}
		else if (tmdSize <= *sizeInOut)
		{
			memcpy(output, tmd, tmdSize);
			result = IPC_SUCCESS;
		}
	}

	return result;
}

s32 WriteTempTmd(const void* data, u32 size)
{
	s32 result = ES_WRITEERROR;
	s32 fd = -1;

	DeletePath(TMP_TMD_PATH);

	result = CreateFile(TMP_TMD_PATH, 0, 3, 3, 0);
	if (result != IPC_SUCCESS)
		return result;

	fd = OpenFile(TMP_TMD_PATH, ReadWrite);
	if (fd < 0)
		return fd;

	result = ES_WRITEERROR;
	if ((u32)WriteFile(fd, data, size) == size)
	{
		result = OSCloseFD(fd);
		fd = -1;
	}

	if (fd >= 0)
		OSCloseFD(fd);
	return result;
}
