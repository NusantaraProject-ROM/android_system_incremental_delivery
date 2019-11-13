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
#include "incfs.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <libgen.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <optional>
#include <string_view>

#include "MountRegistry.h"
#include "path.h"

namespace {
namespace impl {

using namespace std::literals;
using namespace android::incfs;
namespace base = android::base;

struct Control {
    Control(int error) : cmd(error), log(error) {}
    Control(base::unique_fd&& cmd, base::unique_fd&& log)
          : cmd(std::move(cmd)), log(std::move(log)) {}

    base::unique_fd cmd;
    base::unique_fd log;
};

MountRegistry& registry() {
    static MountRegistry instance;
    return instance;
}

base::unique_fd openRaw(std::string_view dir, std::string_view name) {
    auto file = base::StringPrintf("%.*s/%.*s", (int)dir.size(), dir.data(), (int)name.size(),
                                   name.data());
    auto fd = base::unique_fd(TEMP_FAILURE_RETRY(::open(file.c_str(), O_RDWR)));
    if (fd < 0) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] failed to open IncFS file " << file;
        return base::unique_fd{-error};
    }
    return fd;
}

base::unique_fd openCmd(std::string_view dir) {
    return openRaw(dir, ".cmd");
}
base::unique_fd openLog(std::string_view dir) {
    return openRaw(dir, ".log");
}

static std::optional<Version> readIncFsVersion() {
    const std::string sSysfsVersionFile = "/sys/fs/" + std::string(INCFS_NAME) + "/version";

    std::ifstream verFile(sSysfsVersionFile);
    if (!verFile) {
        return {};
    }
    Version version = -1;
    if (!(verFile >> version)) {
        return {};
    }
    return version > 0 ? std::optional(version) : std::nullopt;
}

Version version() {
    return readIncFsVersion().value_or(kVersionNone);
}

// TODO: make this function public in android::fs_mgr.
static bool isFsAvailable(const std::string& filesystem) {
    static constexpr auto kProcFilesystems = "/proc/filesystems"sv;
    std::string filesystems;
    if (!android::base::ReadFileToString(kProcFilesystems.data(), &filesystems)) {
        return false;
    }
    return filesystems.find("\t" + filesystem + "\n") != std::string::npos;
}

bool enabled() {
    // First check if incfs is installed on the device
    if (!isFsAvailable(INCFS_NAME)) {
        return false;
    }
    // Check if property is enabled (default is true)
    // TODO: change default to false
    static constexpr auto kIncrementalEnabledProperty = "persist.incremental.enabled"sv;
    return base::GetBoolProperty(std::string(kIncrementalEnabledProperty), true /*false*/);
}

bool isIncFsPath(const char* path) {
    if (!enabled()) {
        return false;
    }

    struct statfs fs;
    memset(&fs, 0, sizeof(fs));
    if (statfs(path, &fs) != 0) {
        PLOG(ERROR) << "Could not statfs " << path;
        return false;
    }

    return fs.f_type == INCFS_MAGIC_NUMBER;
}

Control mount(std::string_view imagePath, std::string_view targetDir, int32_t flags,
              std::chrono::milliseconds timeout, int mode) {
    if (!enabled()) {
        LOG(WARNING) << "[incfs] Feature is not enabled";
        return {-ENOTSUP};
    }

    if (isIncFsPath(details::c_str(targetDir))) {
        LOG(ERROR) << "[incfs] mounting over existing incfs mount is not allowed";
        return {-EINVAL};
    }

    int openFlags = O_CREAT | O_RDWR | O_CLOEXEC;
    if (flags & android::incfs::createOnly) {
        openFlags |= O_EXCL;
    } else if (flags & android::incfs::truncate) {
        openFlags |= O_TRUNC;
    }
    auto backingFd =
            base::unique_fd(TEMP_FAILURE_RETRY(::open(details::c_str(imagePath), openFlags, mode)));
    if (backingFd < 0) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] failed to open or create an image file: " << imagePath;
        return {-error};
    }

    using namespace std::chrono;
    auto opts = base::StringPrintf("backing_fd=%d,read_timeout_ms=%u,readahead=0,rlog_pages=%u",
                                   backingFd.get(),
                                   (unsigned)duration_cast<milliseconds>(timeout).count(),
                                   unsigned(INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES));
    if (TEMP_FAILURE_RETRY(::mount(INCFS_NAME, details::c_str(targetDir), INCFS_NAME,
                                   MS_NOSUID | MS_NODEV | MS_NOATIME, opts.c_str()))) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] Failed to mount IncFS filesystem: " << targetDir;
        return {-error};
    }

    LOG(DEBUG) << "[incfs] mounted IncFS at " << targetDir << ", backing file " << imagePath
               << ", opts " << opts;

    auto fd = openCmd(targetDir);
    if (fd < 0) {
        unmount(targetDir);
        return {fd};
    }

    registry().addRoot(targetDir);
    return {std::move(fd), openLog(targetDir)};
}

int bindMount(std::string_view source, std::string_view target) {
    if (!enabled()) {
        return -ENOTSUP;
    }

    if (TEMP_FAILURE_RETRY(::mount(details::c_str(source), details::c_str(target), nullptr, MS_BIND,
                                   nullptr))) {
        PLOG(ERROR) << "[incfs] Failed to bind mount " << source << " to " << target;
        return -errno;
    }
    registry().addBind(source, target);
    return 0;
}

int unmount(std::string_view dir) {
    if (!enabled()) {
        return -ENOTSUP;
    }

    registry().removeBind(dir);
    errno = 0;
    if (TEMP_FAILURE_RETRY(::umount2(details::c_str(dir), MNT_FORCE)) == 0 || errno == EINVAL ||
        errno == ENOENT) {
        // EINVAL - not a mount point, ENOENT - doesn't exist at all
        return -errno;
    }
    PLOG(WARNING) << __func__ << ": umount(force) failed, detaching '" << dir << '\'';
    errno = 0;
    if (!TEMP_FAILURE_RETRY(::umount2(details::c_str(dir), MNT_DETACH))) {
        return 0;
    }
    PLOG(INFO) << __func__ << ": umount(detach) returned non-zero for '" << dir << '\'';
    return 0;
}

static int sendInstruction(int fd, incfs_instruction& inst) {
    inst.version = INCFS_HEADER_VER;
    if (::ioctl(fd, INCFS_IOC_PROCESS_INSTRUCTION, (void*)&inst) == 0) {
        return 0;
    }
    return -errno;
}

static int64_t addInodeToDir(int fd, Inode inode, std::string_view name, uint64_t dirInode) {
    LOG(INFO) << __func__ << " @ " << fd << " / " << dirInode << " / " << name << " adding "
              << inode;

    auto inst = incfs_instruction{.type = INCFS_INSTRUCTION_ADD_DIR_ENTRY,
                                  .dir_entry = {.dir_ino = dirInode,
                                                .child_ino = uint64_t(inode),
                                                .name = uint64_t(name.data()),
                                                .name_len = uint16_t(name.size())}};
    const auto res = sendInstruction(fd, inst);
    if (res < 0) {
        LOG(ERROR) << "addInodeToDir failed: " << res;
        return res;
    }
    if (res != 0) {
        return -EIO;
    }
    return int64_t(inode);
}

static Inode makeInode(int fd, std::string_view name, Inode parentInode, Size size, mode_t mode,
                       std::string_view metadata) {
    // TODO(zyy): add signature information

    LOG(INFO) << __func__ << "(" << ((mode & S_IFDIR) ? "dir" : "file") << ") @ " << fd << " / "
              << parentInode << " / " << name << " of " << size << " bytes, '" << metadata << '\'';

    if (metadata.size() > INCFS_MAX_FILE_ATTR_SIZE) {
        LOG(ERROR) << "Input metadata size " << metadata.size() << " is bigger than max "
                   << INCFS_MAX_FILE_ATTR_SIZE;
        return -E2BIG;
    }

    auto inst = incfs_instruction{.type = INCFS_INSTRUCTION_NEW_FILE,
                                  .file = {.size = uint64_t(size),
                                           .mode = uint16_t(mode),
                                           .file_attr_len = uint32_t(metadata.size()),
                                           .file_attr = uint64_t(metadata.data())}};

    auto res = sendInstruction(fd, inst);
    if (res < 0) {
        LOG(ERROR) << "makeInode failed: " << res;
        return res;
    }
    if (res != 0) {
        return -EIO;
    }

    return addInodeToDir(fd, inst.file.ino_out, name, parentInode);
}

Control open(std::string_view dir) {
    auto root = registry().rootFor(dir);
    return {openCmd(root), openLog(root)};
}

Inode makeDir(int fd, std::string_view name, Inode parent, std::string_view metadata, int mode) {
    return makeInode(fd, name, parent, 0, S_IFDIR | (mode & 0777), metadata);
}

Inode makeFile(int fd, std::string_view name, Inode parent, Size size, std::string_view metadata,
               int mode) {
    return makeInode(fd, name, parent, size, S_IFREG | (mode & 0777), metadata);
}

int link(int fd, Inode item, Inode targetParent, std::string_view name) {
    const auto res = addInodeToDir(fd, item, name, targetParent);
    return res < 0 ? int(res) : 0;
}

int unlink(int fd, Inode parent, std::string_view name) {
    incfs_instruction inst = {.type = INCFS_INSTRUCTION_REMOVE_DIR_ENTRY,
                              .dir_entry = {.dir_ino = uint64_t(parent),
                                            .name = uint64_t(name.data()),
                                            .name_len = uint16_t(name.size())}};

    auto res = sendInstruction(fd, inst);
    if (res < 0) {
        return res;
    }
    if (res != 0) {
        return -EIO;
    }
    return 0;
}

int waitForReads(int fd, std::chrono::milliseconds timeout,
                 incfs_pending_read_info pendingReadsBuffer[], size_t* pendingReadsBufferSize) {
    using namespace std::chrono;
    auto hrTimeout = high_resolution_clock::duration(timeout);

    while (hrTimeout > hrTimeout.zero() || (!pendingReadsBuffer && hrTimeout == hrTimeout.zero())) {
        const auto startTs = steady_clock::now();

        pollfd pfd = {fd, POLLIN, 0};
        const auto res = ::poll(&pfd, 1, duration_cast<milliseconds>(hrTimeout).count());
        if (res > 0) {
            break;
        }
        if (res == 0) {
            if (pendingReadsBufferSize) {
                *pendingReadsBufferSize = 0;
            }
            return -ETIMEDOUT;
        }
        const auto error = errno;
        if (error != EINTR) {
            PLOG(ERROR) << "poll() failed";
            return -error;
        }
        hrTimeout -= steady_clock::now() - startTs;
    }
    if (!pendingReadsBuffer) {
        return hrTimeout < hrTimeout.zero() ? -ETIMEDOUT : 0;
    }

    auto res = ::read(fd, pendingReadsBuffer, *pendingReadsBufferSize);
    if (res < 0) {
        const auto error = errno;
        PLOG(ERROR) << "read() failed";
        return -error;
    }
    if (res == 0) {
        *pendingReadsBufferSize = 0;
        return -ETIMEDOUT;
    }
    if ((res % sizeof(*pendingReadsBuffer)) != 0) {
        PLOG(ERROR) << "read() returned half of a struct??";
        return -EFAULT;
    }
    *pendingReadsBufferSize = res / sizeof(*pendingReadsBuffer);
    return 0;
}

int writeBlocks(int fd, const incfs_new_data_block blocks[], int blocksCount) {
    if (blocksCount < 0) {
        return -EINVAL;
    }
    if (blocksCount == 0) {
        return 0;
    }

    auto ptr = blocks;
    const auto end = blocks + blocksCount;
    do {
        const auto written = ::write(fd, ptr, (end - ptr) * sizeof(*ptr));
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            const auto error = errno;
            PLOG(WARNING) << "writing IncFS blocks failed";
            if (ptr == blocks) {
                return -error;
            }
            // something has been written, return a success here and let the
            // next call handle the error.
            break;
        }
        if ((written % sizeof(*ptr)) != 0) {
            PLOG(ERROR) << "write() handled half of an instruction?? " << written;
            return -EFAULT;
        }
        ptr += written / sizeof(*ptr);
    } while (ptr < end);
    return ptr - blocks;
}

std::string root(int fd) {
    auto cmdFile = path::fromFd(fd);
    if (cmdFile.empty()) {
        return {};
    }
    auto res = ::dirname(cmdFile.c_str());
    if (!res || !*res) {
        return {};
    }
    return res;
}

IncFsErrorCode getMetadata(int fd, Inode inode, char buffer[], size_t* bufferSize) {
    incfs_get_file_attr_request request = {
            .version = INCFS_HEADER_VER,
            .ino = uint64_t(inode),
            .file_attr = uint64_t(buffer),
            .file_attr_buf_size = uint32_t(*bufferSize),
    };
    auto res = ::ioctl(fd, INCFS_IOC_READ_FILE_ATTR, &request);
    if (res < 0) {
        PLOG(ERROR) << "Driver call failed for inode " << inode;
        return res;
    }
    if (request.file_attr_len_out > *bufferSize) {
        LOG(ERROR) << "Not enough space in the buffer, " << request.file_attr_len_out << " vs "
                   << INCFS_MAX_FILE_ATTR_SIZE << " max allowed in the driver API";
        return -EOVERFLOW;
    }
    *bufferSize = request.file_attr_len_out;
    return 0;
}

} // namespace impl
} // namespace

bool IncFs_Enabled() {
    return impl::enabled();
}
IncFsVersion IncFs_Version() {
    return impl::version();
}

IncFsErrorCode IncFs_IsIncFsPath(const char* path) {
    return impl::isIncFsPath(path);
}

IncFsControl IncFs_Mount(const char* imagePath, const char* targetDir, int32_t flags,
                         int32_t timeoutMs, int32_t mode) {
    auto control =
            impl::mount(imagePath, targetDir, flags, std::chrono::milliseconds(timeoutMs), mode);
    return {control.cmd.release(), control.log.release()};
}
IncFsErrorCode IncFs_Unmount(const char* dir) {
    return impl::unmount(dir);
}
IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir) {
    return impl::bindMount(sourceDir, targetDir);
}

IncFsErrorCode IncFs_Root(IncFsControl control, char buffer[], size_t* bufferSize) {
    std::string result = impl::root(control.cmdFd);
    if (*bufferSize <= result.size()) {
        return -EOVERFLOW;
    }
    *bufferSize = result.size();
    result.copy(buffer, *bufferSize, 0);
    buffer[*bufferSize] = '\0';
    return 0;
}

IncFsControl IncFs_Open(const char* dir) {
    auto control = impl::open(dir);
    return {control.cmd.release(), control.log.release()};
}
IncFsInode IncFs_MakeFile(IncFsControl control, const char* name, IncFsInode parent, IncFsSize size,
                          const char metadata[], size_t metadataSize, int32_t mode) {
    return impl::makeFile(control.cmdFd, name, parent, size,
                          std::string_view(metadata, metadataSize), mode);
}
IncFsInode IncFs_MakeDir(IncFsControl control, const char* name, IncFsInode parent,
                         const char metadata[], size_t metadataSize, int32_t mode) {
    return impl::makeDir(control.cmdFd, name, parent, std::string_view(metadata, metadataSize),
                         mode);
}

IncFsErrorCode IncFs_GetMetadata(IncFsControl control, IncFsInode inode, char buffer[],
                                 size_t* bufferSize) {
    return impl::getMetadata(control.cmdFd, inode, buffer, bufferSize);
}

IncFsErrorCode IncFs_Link(IncFsControl control, IncFsInode item, IncFsInode targetParent,
                          const char* name) {
    return impl::link(control.cmdFd, item, targetParent, name);
}
IncFsErrorCode IncFs_Unlink(IncFsControl control, IncFsInode parent, const char* name) {
    return impl::unlink(control.cmdFd, parent, name);
}

IncFsErrorCode IncFs_WaitForPendingReads(IncFsControl control, int32_t timeoutMs,
                                         IncFsPendingReadInfo buffer[], size_t* bufferSize) {
    return impl::waitForReads(control.cmdFd, std::chrono::milliseconds(timeoutMs), buffer,
                              bufferSize);
}

IncFsErrorCode IncFs_WaitForPageReads(IncFsControl control, int32_t timeoutMs,
                                      IncFsPageReadInfo buffer[], size_t* bufferSize) {
    if (control.logFd < 0) {
        return -EINVAL;
    }
    return impl::waitForReads(control.logFd, std::chrono::milliseconds(timeoutMs), buffer,
                              bufferSize);
}

IncFsErrorCode IncFs_WriteBlocks(IncFsControl control, const incfs_new_data_block blocks[],
                                 size_t blocksCount) {
    return impl::writeBlocks(control.cmdFd, blocks, blocksCount);
}
