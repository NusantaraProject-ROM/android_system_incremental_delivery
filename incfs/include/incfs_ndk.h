/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H
#define ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H

#include <linux/incrementalfs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#define INCFS_LIBRARY_NAME "libincfs.so"

typedef struct {
    union {
        char data[16];
        int64_t for_alignment;
    };
} IncFsFileId;

static const IncFsFileId kIncFsInvalidFileId = {
        {{(char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1,
          (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1, (char)-1}}};

static const int kIncFsFileIdStringLength = sizeof(IncFsFileId) * 2;

typedef enum {
    INCFS_FEATURE_NONE = 0,
    INCFS_FEATURE_CORE = 1,
} IncFsFeatures;

typedef int IncFsErrorCode;
typedef int64_t IncFsSize;
typedef int32_t IncFsBlockIndex;
typedef int IncFsFd;
typedef struct {
    IncFsFd cmd;
    IncFsFd pendingReads;
    IncFsFd logs;
} IncFsControl;

typedef struct {
    const char* data;
    IncFsSize size;
} IncFsSpan;

typedef enum {
    INCFS_DEFAULT_READ_TIMEOUT_MS = 10000,
    INCFS_DEFAULT_PENDING_READ_BUFFER_SIZE = 24,
    INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES = 2
} IncFsDefaults;

typedef enum {
    INCFS_MOUNT_CREATE_ONLY = 1,
    INCFS_MOUNT_TRUNCATE = 2,
} IncFsMountFlags;

typedef enum {
    INCFS_HASH_NONE,
    INCFS_HASH_SHA256,
} IncFsHashAlgortithm;

typedef struct {
    IncFsMountFlags flags;
    int32_t defaultReadTimeoutMs;
    int32_t readLogBufferPages;
    int32_t readLogDisableAfterTimeoutMs;
} IncFsMountOptions;

typedef enum {
    INCFS_COMPRESSION_KIND_NONE,
    INCFS_COMPRESSION_KIND_LZ4,
} IncFsCompressionKind;

typedef enum {
    INCFS_BLOCK_KIND_DATA,
    INCFS_BLOCK_KIND_HASH,
} IncFsBlockKind;

typedef struct {
    IncFsFd fileFd;
    IncFsBlockIndex pageIndex;
    IncFsCompressionKind compression;
    IncFsBlockKind kind;
    uint32_t dataSize;
    const char* data;
} IncFsDataBlock;

typedef struct {
    IncFsSize size;
    IncFsSpan metadata;
    IncFsSpan signature;
} IncFsNewFileParams;

typedef struct {
    IncFsFileId id;
    uint64_t bootClockTsUs;
    IncFsBlockIndex block;
    uint32_t serialNo;
} IncFsReadInfo;

// All functions return -errno in case of failure.
// All IncFsFd functions return >=0 in case of success.
// All IncFsFileId functions return invalid IncFsFileId on error.
// All IncFsErrorCode functions return 0 in case of success.

bool IncFs_IsEnabled();
IncFsFeatures IncFs_Features();

bool IncFs_IsIncFsPath(const char* path);

static inline bool IncFs_IsValidFileId(IncFsFileId fileId) {
    return memcmp(&fileId, &kIncFsInvalidFileId, sizeof(fileId)) != 0;
}

int IncFs_FileIdToString(IncFsFileId id, char* out);
IncFsFileId IncFs_FileIdFromString(const char* in);

IncFsFileId IncFs_FileIdFromMetadata(IncFsSpan metadata);

IncFsControl IncFs_Mount(const char* backingPath, const char* targetDir, IncFsMountOptions options);
IncFsControl IncFs_Open(const char* dir);
IncFsErrorCode IncFs_SetOptions(IncFsControl control, IncFsMountOptions options);

IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir);
IncFsErrorCode IncFs_Unmount(const char* dir);

IncFsErrorCode IncFs_Root(IncFsControl control, char buffer[], size_t* bufferSize);

IncFsErrorCode IncFs_MakeFile(IncFsControl control, const char* path, int32_t mode, IncFsFileId id,
                              IncFsNewFileParams params);
IncFsErrorCode IncFs_MakeDir(IncFsControl control, const char* path, int32_t mode);

IncFsErrorCode IncFs_GetMetadataById(IncFsControl control, IncFsFileId id, char buffer[],
                                     size_t* bufferSize);
IncFsErrorCode IncFs_GetMetadataByPath(IncFsControl control, const char* path, char buffer[],
                                       size_t* bufferSize);

IncFsErrorCode IncFs_GetSignatureById(IncFsControl control, IncFsFileId id, char buffer[],
                                      size_t* bufferSize);
IncFsErrorCode IncFs_GetSignatureByPath(IncFsControl control, const char* path, char buffer[],
                                        size_t* bufferSize);
IncFsErrorCode IncFs_UnsafeGetSignatureByPath(const char* path, char buffer[], size_t* bufferSize);

IncFsFileId IncFs_GetId(IncFsControl control, const char* path);

IncFsErrorCode IncFs_Link(IncFsControl control, const char* sourcePath, const char* targetPath);
IncFsErrorCode IncFs_Unlink(IncFsControl control, const char* path);

IncFsErrorCode IncFs_WaitForPendingReads(IncFsControl control, int32_t timeoutMs,
                                         IncFsReadInfo buffer[], size_t* bufferSize);
IncFsErrorCode IncFs_WaitForPageReads(IncFsControl control, int32_t timeoutMs,
                                      IncFsReadInfo buffer[], size_t* bufferSize);

IncFsFd IncFs_OpenWriteByPath(IncFsControl control, const char* path);
IncFsFd IncFs_OpenWriteById(IncFsControl control, IncFsFileId id);

IncFsErrorCode IncFs_WriteBlocks(const IncFsDataBlock blocks[], size_t blocksCount);

__END_DECLS

#endif // ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H
