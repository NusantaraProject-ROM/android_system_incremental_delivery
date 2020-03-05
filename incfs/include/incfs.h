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

#include <unistd.h>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "incfs_ndk.h"

namespace android::incfs {

enum MountFlags {
    createOnly = INCFS_MOUNT_CREATE_ONLY,
    truncate = INCFS_MOUNT_TRUNCATE,
};

enum Features {
    none = INCFS_FEATURE_NONE,
    core = INCFS_FEATURE_CORE,
    externalId = INCFS_FEATURE_EXTERNAL_ID,
    uidTimeouts = INCFS_FEATURE_UID_TIMEOUTS,
};

enum class HashAlgorithm {
    none = INCFS_HASH_NONE,
    sha256 = INCFS_HASH_SHA256,
};

enum class CompressionKind {
    none = INCFS_COMPRESSION_KIND_NONE,
    lz4 = INCFS_COMPRESSION_KIND_LZ4,
};

enum class BlockKind {
    data = INCFS_BLOCK_KIND_DATA,
    hash = INCFS_BLOCK_KIND_HASH,
};

using Control = IncFsControl;

struct UniqueControl final : Control {
    UniqueControl(Control c) : Control(c) {}
    UniqueControl() : UniqueControl({-1, -1, -1}) {}

    ~UniqueControl() { reset(); }

    UniqueControl(UniqueControl&& other) noexcept {
        cmd = std::exchange(other.cmd, -1);
        logs = std::exchange(other.logs, -1);
        pendingReads = std::exchange(other.pendingReads, -1);
    }

    UniqueControl& operator=(UniqueControl&& other) {
        this->~UniqueControl();
        new (this) UniqueControl(std::move(other));
        return *this;
    }

    [[nodiscard]] Control release() {
        Control res = *this;
        cmd = logs = pendingReads = -1;
        return res;
    }

    void reset() {
        if (cmd >= 0) {
            close(cmd);
        }
        if (logs >= 0) {
            close(logs);
        }
        if (pendingReads >= 0) {
            close(pendingReads);
        }
        cmd = logs = pendingReads = -1;
    }
};

// A mini version of std::span
template <class T>
class Span {
public:
    using iterator = T*;
    using const_iterator = const T*;

    constexpr Span(T* array, size_t length) : ptr_(array), len_(length) {}
    template <typename V>
    constexpr Span(const std::vector<V>& x) : Span(x.data(), x.size()) {}

    constexpr T* data() const { return ptr_; }
    constexpr size_t size() const { return len_; }
    constexpr T& operator[](size_t i) const { return *(data() + i); }
    constexpr iterator begin() const { return data(); }
    constexpr const_iterator cbegin() const { return begin(); }
    constexpr iterator end() const { return data() + size(); }
    constexpr const_iterator cend() const { return end(); }

private:
    T* ptr_;
    size_t len_;
};

using FileId = IncFsFileId;
using Size = IncFsSize;
using BlockIndex = IncFsBlockIndex;
using ErrorCode = IncFsErrorCode;
using Fd = IncFsFd;
using ReadInfo = IncFsReadInfo;
using RawMetadata = std::vector<char>;
using RawSignature = std::vector<char>;
using UidReadTimeout = IncFsUidReadTimeout;
using MountOptions = IncFsMountOptions;
using DataBlock = IncFsDataBlock;
using NewFileParams = IncFsNewFileParams;

constexpr auto kDefaultReadTimeout = std::chrono::milliseconds(INCFS_DEFAULT_READ_TIMEOUT_MS);
constexpr int kBlockSize = INCFS_DATA_FILE_BLOCK_SIZE;
const auto kInvalidFileId = kIncFsInvalidFileId;

bool enabled();
Features features();
bool isValidFileId(FileId fileId);
std::string toString(FileId fileId);
IncFsFileId toFileId(std::string_view str);
bool isIncFsPath(std::string_view path);

UniqueControl mount(std::string_view backingPath, std::string_view targetDir, MountOptions options);
UniqueControl open(std::string_view dir);
ErrorCode setOptions(Control control, MountOptions newOptions);

ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir);
ErrorCode unmount(std::string_view dir);

std::string root(Control control);

ErrorCode makeFile(Control control, std::string_view path, int mode, FileId fileId,
                   NewFileParams params);
ErrorCode makeDir(Control control, std::string_view path, int mode = 0555);

RawMetadata getMetadata(Control control, FileId fileId);
RawMetadata getMetadata(Control control, std::string_view path);
FileId getFileId(Control control, std::string_view path);

RawSignature getSignature(Control control, FileId fileId);
RawSignature getSignature(Control control, std::string_view path);

ErrorCode link(Control control, std::string_view sourcePath, std::string_view targetPath);
ErrorCode unlink(Control control, std::string_view path);

enum class WaitResult { HaveData, Timeout, Error };

WaitResult waitForPendingReads(Control control, std::chrono::milliseconds timeout,
                               std::vector<ReadInfo>* pendingReadsBuffer);
WaitResult waitForPageReads(Control control, std::chrono::milliseconds timeout,
                            std::vector<ReadInfo>* pageReadsBuffer);

// Returns a file descriptor that needs to be closed.
int openWrite(Control control, FileId fileId);
// Returns a file descriptor that needs to be closed.
int openWrite(Control control, std::string_view path);
ErrorCode writeBlocks(Span<const DataBlock> blocks);

} // namespace android::incfs

bool operator==(const IncFsFileId& l, const IncFsFileId& r);
inline bool operator!=(const IncFsFileId& l, const IncFsFileId& r) {
    return !(l == r);
}

namespace std {

template <>
struct hash<IncFsFileId> {
    size_t operator()(const IncFsFileId& id) const noexcept {
        return std::hash<std::string_view>()({&id.data[0], sizeof(id)});
    }
};

} // namespace std

#include "incfs_inline.h"
