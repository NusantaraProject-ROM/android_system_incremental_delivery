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
#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t
#include <stdint.h>  // for int*_t
#include <sys/cdefs.h>

__BEGIN_DECLS

#define INCFS_LIBRARY_NAME "libincfs.so"

typedef int64_t IncFsInode;
typedef int32_t IncFsVersion;
typedef int64_t IncFsSize;
typedef int32_t IncFsBlockIndex;
typedef struct {
    int cmdFd;
    int logFd;
} IncFsControl;
typedef int IncFsErrorCode;

enum { INCFS_VERSION_NONE = 0 };
enum { INCFS_DEFAULT_READ_TIMEOUT_MS = 10000 };
enum { INCFS_DEFAULT_PENDING_READ_BUFFER_SIZE = 24 };
enum { INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES = 2 };

typedef struct incfs_pending_read_info IncFsPendingReadInfo;
typedef IncFsPendingReadInfo IncFsPageReadInfo;

typedef enum {
    INCFS_MOUNT_CREATE_ONLY = 1,
    INCFS_MOUNT_TRUNCATE = 2,
} IncFsMountFlags;

// All functions return -errno in case of failure.
// All IncFsFd/IncFsInode functions return >=0 in case of success.
// All IncFsErrorCode functions return 0 in case of success.

bool IncFs_Enabled();
IncFsVersion IncFs_Version();

IncFsErrorCode IncFs_IsIncFsPath(const char* path);

IncFsControl IncFs_Mount(const char* imagePath, const char* targetDir, int32_t flags /*= 0*/,
                         int32_t timeoutMs /*= INCFS_DEFAULT_READ_TIMEOUT_MS*/,
                         int32_t mode /*= 0777*/);
IncFsErrorCode IncFs_Unmount(const char* dir);
IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir);

IncFsErrorCode IncFs_Root(IncFsControl control, char buffer[], size_t* bufferSize);

IncFsControl IncFs_Open(const char* dir);
IncFsInode IncFs_MakeFile(IncFsControl control, const char* name, IncFsInode parent, IncFsSize size,
                          const char metadata[], size_t metadataSize, int32_t mode /*= 0555*/);
IncFsInode IncFs_MakeDir(IncFsControl control, const char* name, IncFsInode parent,
                         const char metadata[], size_t metadataSize, int32_t mode /*= 0555*/);

// INCFS_MAX_FILE_ATTR_SIZE
IncFsErrorCode IncFs_GetMetadata(IncFsControl control, IncFsInode inode, char buffer[],
                                 size_t* bufferSize);

IncFsErrorCode IncFs_Link(IncFsControl control, IncFsInode item, IncFsInode targetParent,
                          const char* name);
IncFsErrorCode IncFs_Unlink(IncFsControl control, IncFsInode parent, const char* name);

IncFsErrorCode IncFs_WaitForPendingReads(IncFsControl control, int32_t timeoutMs,
                                         IncFsPendingReadInfo buffer[], size_t* bufferSize);
IncFsErrorCode IncFs_WaitForPageReads(IncFsControl control, int32_t timeoutMs,
                                      IncFsPageReadInfo buffer[], size_t* bufferSize);

IncFsErrorCode IncFs_WriteBlocks(IncFsControl control, const struct incfs_new_data_block blocks[],
                                 size_t blocksCount);

__END_DECLS

#endif // ANDROID_INCREMENTAL_FILE_SYSTEM_NDK_H
