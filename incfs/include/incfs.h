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
#pragma once

#include <errno.h>

#include <chrono>
#include <string_view>
#include <vector>

#include "incfs_ndk.h"

namespace android::incfs {

using Control = IncFsControl;
using Inode = IncFsInode;
using Version = IncFsVersion;
using Size = IncFsSize;
using BlockIndex = IncFsBlockIndex;
using ErrorCode = IncFsErrorCode;
using PendingReadInfo = IncFsPendingReadInfo;
using PageReadInfo = IncFsPageReadInfo;
using RawMetadata = std::vector<char>;

constexpr Version kVersionNone = INCFS_VERSION_NONE;
constexpr std::chrono::milliseconds kDefaultReadTimeout =
        std::chrono::milliseconds(INCFS_DEFAULT_READ_TIMEOUT_MS);
constexpr int kBlockSize = INCFS_DATA_FILE_BLOCK_SIZE;

bool enabled();
Version version();

bool isIncFsPath(std::string_view path);

enum MountFlags {
    createOnly = 1,
    truncate = 2,
};

Control mount(std::string_view imagePath, std::string_view targetDir, int32_t flags = 0,
              std::chrono::milliseconds timeout = kDefaultReadTimeout, int mode = 0777);
ErrorCode unmount(std::string_view dir);
ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir);

std::string root(Control control);

Control open(std::string_view dir);
Inode makeFile(Control control, std::string_view name, Inode parent, Size size,
               std::string_view metadata, int mode = 0555);
Inode makeDir(Control control, std::string_view name, Inode parent, std::string_view metadata,
              int mode = 0555);

RawMetadata getMetadata(Control control, Inode inode);

ErrorCode link(Control control, Inode item, Inode targetParent, std::string_view name);
ErrorCode unlink(Control control, Inode parent, std::string_view name);

enum class WaitResult { HaveData, Timeout, Error };

WaitResult waitForPendingReads(Control control, std::chrono::milliseconds timeout,
                               std::vector<PendingReadInfo>* pendingReadsBuffer);
WaitResult waitForPageReads(Control control, std::chrono::milliseconds timeout,
                            std::vector<PageReadInfo>* pageReadsBuffer);

ErrorCode writeBlocks(Control control, const incfs_new_data_block blocks[], int blocksCount);

} // namespace android::incfs

#include "incfs_inline.h"
