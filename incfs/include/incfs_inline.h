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

#include <optional>
#include <string>

namespace android::incfs {

namespace details {

class CStrWrapper {
public:
    CStrWrapper(std::string_view sv) {
        if (sv[sv.size()] == '\0') {
            mCstr = sv.data();
        } else {
            mCopy.emplace(sv);
            mCstr = mCopy->c_str();
        }
    }

    CStrWrapper(const CStrWrapper&) = delete;
    void operator=(const CStrWrapper&) = delete;
    CStrWrapper(CStrWrapper&&) = delete;
    void operator=(CStrWrapper&&) = delete;

    const char* get() const { return mCstr; }
    operator const char*() const { return get(); }

private:
    const char* mCstr;
    std::optional<std::string> mCopy;
};

inline CStrWrapper c_str(std::string_view sv) {
    return {sv};
}

} // namespace details

inline bool enabled() {
    return IncFs_Enabled();
}
inline Version version() {
    return IncFs_Version();
}

inline bool isIncFsPath(std::string_view path) {
    return IncFs_IsIncFsPath(details::c_str(path));
}

inline Control mount(std::string_view imagePath, std::string_view targetDir, int32_t flags,
                     std::chrono::milliseconds timeout, int mode) {
    return IncFs_Mount(details::c_str(imagePath), details::c_str(targetDir), flags, timeout.count(),
                       mode);
}
inline ErrorCode unmount(std::string_view dir) {
    return IncFs_Unmount(details::c_str(dir));
}
inline ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir) {
    return IncFs_BindMount(details::c_str(sourceDir), details::c_str(targetDir));
}

inline std::string root(Control control) {
    std::string result;
    result.resize(PATH_MAX);
    size_t size = result.size();
    if (IncFs_Root(control, result.data(), &size) < 0) {
        return {};
    }
    result.resize(size);
    return result;
}

inline Control open(std::string_view dir) {
    return IncFs_Open(details::c_str(dir));
}
inline Inode makeFile(Control control, std::string_view name, Inode parent, Size size,
                      std::string_view metadata, int mode) {
    return IncFs_MakeFile(control, details::c_str(name), parent, size, metadata.begin(),
                          metadata.size(), mode);
}
inline Inode makeDir(Control control, std::string_view name, Inode parent,
                     std::string_view metadata, int mode) {
    return IncFs_MakeDir(control, details::c_str(name), parent, metadata.begin(), metadata.size(),
                         mode);
}

inline RawMetadata getMetadata(Control control, Inode inode) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (IncFs_GetMetadata(control, inode, metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline ErrorCode link(Control control, Inode item, Inode targetParent, std::string_view name) {
    return IncFs_Link(control, item, targetParent, details::c_str(name));
}
inline ErrorCode unlink(Control control, Inode parent, std::string_view name) {
    return IncFs_Unlink(control, parent, details::c_str(name));
}

inline WaitResult waitForPendingReads(Control control, std::chrono::milliseconds timeout,
                                      std::vector<PendingReadInfo>* pendingReadsBuffer) {
    static constexpr auto kDefaultBufferSize = INCFS_DEFAULT_PENDING_READ_BUFFER_SIZE;
    if (pendingReadsBuffer->empty()) {
        pendingReadsBuffer->resize(kDefaultBufferSize);
    }
    size_t size = pendingReadsBuffer->size();
    IncFsErrorCode err =
            IncFs_WaitForPendingReads(control, timeout.count(), pendingReadsBuffer->data(), &size);
    pendingReadsBuffer->resize(size);
    switch (err) {
        case 0:
            return WaitResult::HaveData;
        case -ETIMEDOUT:
            return WaitResult::Timeout;
    }
    return WaitResult(err);
}

inline WaitResult waitForPageReads(Control control, std::chrono::milliseconds timeout,
                                   std::vector<PageReadInfo>* pageReadsBuffer) {
    static constexpr auto kDefaultBufferSize =
            INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES * PAGE_SIZE / sizeof(PageReadInfo);
    if (pageReadsBuffer->empty()) {
        pageReadsBuffer->resize(kDefaultBufferSize);
    }
    size_t size = pageReadsBuffer->size();
    IncFsErrorCode err =
            IncFs_WaitForPageReads(control, timeout.count(), pageReadsBuffer->data(), &size);
    pageReadsBuffer->resize(size);
    switch (err) {
        case 0:
            return WaitResult::HaveData;
        case -ETIMEDOUT:
            return WaitResult::Timeout;
    }
    return WaitResult(err);
}

inline ErrorCode writeBlocks(Control control, const incfs_new_data_block blocks[],
                             int blocksCount) {
    return IncFs_WriteBlocks(control, blocks, blocksCount);
}

} // namespace android::incfs
