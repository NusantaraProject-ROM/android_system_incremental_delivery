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

#include <optional>
#include <string>

#include "incfs.h"

namespace android::incfs {

constexpr char kIdAttrName[] = INCFS_XATTR_ID_NAME;
constexpr char kSizeAttrName[] = INCFS_XATTR_SIZE_NAME;
constexpr char kMetadataAttrName[] = INCFS_XATTR_METADATA_NAME;

constexpr char kIndexDir[] = ".index";

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
    return IncFs_IsEnabled();
}

inline Features features() {
    return Features(IncFs_Features());
}

inline bool isIncFsPath(std::string_view path) {
    return IncFs_IsIncFsPath(details::c_str(path));
}

inline bool isValidFileId(FileId fileId) {
    return IncFs_IsValidFileId(fileId);
}

inline std::string toString(FileId fileId) {
    std::string res(kIncFsFileIdStringLength, '\0');
    auto err = IncFs_FileIdToString(fileId, res.data());
    if (err) {
        errno = err;
        return {};
    }
    return res;
}

inline IncFsFileId toFileId(std::string_view str) {
    if (str.size() != kIncFsFileIdStringLength) {
        return kIncFsInvalidFileId;
    }
    return IncFs_FileIdFromString(str.data());
}

inline UniqueControl mount(std::string_view backingPath, std::string_view targetDir,
                           MountOptions options) {
    return IncFs_Mount(details::c_str(backingPath), details::c_str(targetDir), options);
}

inline UniqueControl open(std::string_view dir) {
    return IncFs_Open(details::c_str(dir));
}

inline ErrorCode setOptions(Control control, MountOptions newOptions) {
    return IncFs_SetOptions(control, newOptions);
}

inline ErrorCode bindMount(std::string_view sourceDir, std::string_view targetDir) {
    return IncFs_BindMount(details::c_str(sourceDir), details::c_str(targetDir));
}

inline ErrorCode unmount(std::string_view dir) {
    return IncFs_Unmount(details::c_str(dir));
}

inline std::string root(Control control) {
    std::string result;
    result.resize(PATH_MAX);
    size_t size = result.size();
    if (auto err = IncFs_Root(control, result.data(), &size); err < 0) {
        errno = -err;
        return {};
    }
    result.resize(size);
    return result;
}

inline ErrorCode makeFile(Control control, std::string_view path, int mode, FileId fileId,
                          NewFileParams params) {
    return IncFs_MakeFile(control, details::c_str(path), mode, fileId, params);
}
inline ErrorCode makeDir(Control control, std::string_view path, int mode) {
    return IncFs_MakeDir(control, details::c_str(path), mode);
}

inline RawMetadata getMetadata(Control control, FileId fileId) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (IncFs_GetMetadataById(control, fileId, metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline RawMetadata getMetadata(Control control, std::string_view path) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (IncFs_GetMetadataByPath(control, details::c_str(path), metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline RawSignature getSignature(Control control, FileId fileId) {
    RawSignature signature(INCFS_MAX_SIGNATURE_SIZE);
    size_t size = signature.size();
    if (IncFs_GetSignatureById(control, fileId, signature.data(), &size) < 0) {
        return {};
    }
    signature.resize(size);
    return signature;
}

inline RawSignature getSignature(Control control, std::string_view path) {
    RawSignature signature(INCFS_MAX_SIGNATURE_SIZE);
    size_t size = signature.size();
    if (IncFs_GetSignatureByPath(control, details::c_str(path), signature.data(), &size) < 0) {
        return {};
    }
    signature.resize(size);
    return signature;
}

inline FileId getFileId(Control control, std::string_view path) {
    return IncFs_GetId(control, details::c_str(path));
}

inline ErrorCode link(Control control, std::string_view sourcePath, std::string_view targetPath) {
    return IncFs_Link(control, details::c_str(sourcePath), details::c_str(targetPath));
}

inline ErrorCode unlink(Control control, std::string_view path) {
    return IncFs_Unlink(control, details::c_str(path));
}

inline WaitResult waitForPendingReads(Control control, std::chrono::milliseconds timeout,
                                      std::vector<ReadInfo>* pendingReadsBuffer) {
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
                                   std::vector<ReadInfo>* pageReadsBuffer) {
    static constexpr auto kDefaultBufferSize =
            INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES * PAGE_SIZE / sizeof(ReadInfo);
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

inline int openWrite(Control control, FileId fileId) {
    return IncFs_OpenWriteById(control, fileId);
}
inline int openWrite(Control control, std::string_view path) {
    return IncFs_OpenWriteByPath(control, details::c_str(path));
}

inline ErrorCode writeBlocks(std::span<const DataBlock> blocks) {
    return IncFs_WriteBlocks(blocks.data(), blocks.size());
}

} // namespace android::incfs

inline bool operator==(const IncFsFileId& l, const IncFsFileId& r) {
    return memcmp(&l, &r, sizeof(l)) == 0;
}
