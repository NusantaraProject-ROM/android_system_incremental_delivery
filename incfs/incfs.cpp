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
#include <android-base/parsebool.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/sha.h>
#include <selinux/android.h>
#include <selinux/selinux.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string_view>

#include "MountRegistry.h"
#include "path.h"

using namespace std::literals;
using namespace android::incfs;
namespace ab = android::base;

static MountRegistry& registry() {
    static MountRegistry instance;
    return instance;
}

static ab::unique_fd openRaw(std::string_view file) {
    auto fd = ab::unique_fd(::open(details::c_str(file), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        return ab::unique_fd{-errno};
    }
    return fd;
}

static ab::unique_fd openRaw(std::string_view dir, std::string_view name) {
    return openRaw(path::join(dir, name));
}

static ab::unique_fd openCmd(std::string_view dir) {
    return openRaw(dir, INCFS_PENDING_READS_FILENAME);
}
static ab::unique_fd openLog(std::string_view dir) {
    return openRaw(dir, INCFS_LOG_FILENAME);
}
static ab::unique_fd openPendingReads(std::string_view dir) {
    return openRaw(dir, INCFS_PENDING_READS_FILENAME);
}

static std::string root(int fd) {
    auto cmdFile = path::fromFd(fd);
    if (cmdFile.empty()) {
        LOG(INFO) << __func__ << "(): name empty for " << fd;
        return {};
    }
    auto res = path::dirName(cmdFile);
    if (res.empty()) {
        LOG(INFO) << __func__ << "(): dirname empty for " << cmdFile;
        return {};
    }
    if (cmdFile.data() == res.data() || cmdFile.starts_with(res)) {
        cmdFile.resize(res.size());
        return cmdFile;
    }
    return std::string(res);
}

static Features readIncFsFeatures() {
    static const char kSysfsFeaturesDir[] = "/sys/fs/" INCFS_NAME "/features";
    const auto dir = path::openDir(kSysfsFeaturesDir);
    if (!dir) {
        return Features::none;
    }

    int res = Features::none;
    while (auto entry = ::readdir(dir.get())) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        if (entry->d_name == "corefs"sv) {
            res |= Features::core | Features::externalId;
        }
        if (entry->d_name == "uid_timeouts"sv) {
            res |= Features::uidTimeouts;
        }
    }

    return Features(res);
}

IncFsFeatures IncFs_Features() {
    return IncFsFeatures(readIncFsFeatures());
}

static bool isFsAvailable() {
    static const char kProcFilesystems[] = "/proc/filesystems";
    std::string filesystems;
    if (!ab::ReadFileToString(kProcFilesystems, &filesystems)) {
        return false;
    }
    return filesystems.find("\t" INCFS_NAME "\n") != std::string::npos;
}

std::string_view incFsPropertyValue() {
    static const std::string kValue = ab::GetProperty("ro.incremental.enable"s, {});
    return kValue;
}

static std::pair<bool, std::string_view> parseProperty(std::string_view property) {
    auto boolVal = ab::ParseBool(property);
    if (boolVal == ab::ParseBoolResult::kTrue) {
        return {isFsAvailable(), {}};
    }
    if (boolVal == ab::ParseBoolResult::kFalse) {
        return {false, {}};
    }

    // Don't load the module at once, but instead only check if it is loadable.
    static const auto kModulePrefix = "module:"sv;
    if (property.starts_with(kModulePrefix)) {
        const auto modulePath = property.substr(kModulePrefix.size());
        return {::access(details::c_str(modulePath), R_OK | X_OK), modulePath};
    }
    return {false, {}};
}

namespace {

class IncFsInit {
public:
    IncFsInit() {
        auto [featureEnabled, moduleName] = parseProperty(incFsPropertyValue());
        featureEnabled_ = featureEnabled;
        moduleName_ = moduleName;
        loaded_ = featureEnabled_ && isFsAvailable();
    }

    bool enabled() const { return featureEnabled_; }
    bool enabledAndReady() const {
        if (!featureEnabled_) {
            return false;
        }
        if (moduleName_.empty()) {
            return true;
        }
        if (loaded_) {
            return true;
        }
        std::call_once(loadedFlag_, [this] {
            const ab::unique_fd fd(TEMP_FAILURE_RETRY(
                    ::open(details::c_str(moduleName_), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
            if (fd < 0) {
                PLOG(ERROR) << "could not open IncFs kernel module \"" << moduleName_ << '"';
                return;
            }

            const auto rc = syscall(__NR_finit_module, fd.get(), "", 0);
            if (rc < 0) {
                PLOG(ERROR) << "finit_module for IncFs \"" << moduleName_ << "\" failed";
                return;
            }
            if (!isFsAvailable()) {
                LOG(ERROR) << "loaded IncFs kernel module \"" << moduleName_
                           << "\" but incremental-fs is still not available";
            }
            loaded_ = true;
            LOG(INFO) << "successfully loaded IncFs kernel module \"" << moduleName_ << '"';
        });
        return loaded_;
    }

private:
    bool featureEnabled_;
    std::string_view moduleName_;
    mutable std::once_flag loadedFlag_;
    mutable bool loaded_;
};

} // namespace

static IncFsInit& init() {
    static IncFsInit initer;
    return initer;
}

bool IncFs_IsEnabled() {
    return init().enabled();
}

bool isIncFsPath(const char* path) {
    struct statfs fs = {};
    if (::statfs(path, &fs) != 0) {
        PLOG(ERROR) << __func__ << "(): could not statfs " << path;
        return false;
    }

    return fs.f_type == (decltype(fs.f_type))INCFS_MAGIC_NUMBER;
}

static int isDir(const char* path) {
    struct stat st;
    if (::stat(path, &st) != 0) {
        return -errno;
    }
    if (!S_ISDIR(st.st_mode)) {
        return -ENOTDIR;
    }
    return 0;
}

static bool isAbsolute(const char* path) {
    return path && path[0] == '/';
}

static int isValidMountTarget(const char* path) {
    if (!isAbsolute(path)) {
        return -EINVAL;
    }
    if (isIncFsPath(path)) {
        LOG(ERROR) << "[incfs] mounting over existing incfs mount is not allowed";
        return -EINVAL;
    }
    if (const auto err = isDir(path); err != 0) {
        return err;
    }
    if (const auto err = path::isEmptyDir(path); err != 0) {
        return err;
    }
    return 0;
}

static int rmDirContent(const char* path) {
    auto dir = path::openDir(path);
    if (!dir) {
        return -EINVAL;
    }
    while (auto entry = ::readdir(dir.get())) {
        if (entry->d_name == "."sv || entry->d_name == ".."sv) {
            continue;
        }
        auto fullPath = ab::StringPrintf("%s/%s", path, entry->d_name);
        if (entry->d_type == DT_DIR) {
            if (const auto err = rmDirContent(fullPath.c_str()); err != 0) {
                return err;
            }
            if (const auto err = ::rmdir(fullPath.c_str()); err != 0) {
                return err;
            }
        } else {
            if (const auto err = ::unlink(fullPath.c_str()); err != 0) {
                return err;
            }
        }
    }
    return 0;
}

static std::string makeMountOptionsString(IncFsMountOptions options) {
    return ab::StringPrintf("read_timeout_ms=%u,readahead=0,rlog_pages=%u,rlog_wakeup_cnt=1",
                            unsigned(options.defaultReadTimeoutMs),
                            unsigned(options.readLogBufferPages < 0
                                             ? INCFS_DEFAULT_PAGE_READ_BUFFER_PAGES
                                             : options.readLogBufferPages));
}

static UniqueControl makeControl(const char* root) {
    UniqueControl uc;
    uc.cmd = openCmd(root).release();
    if (uc.cmd < 0) {
        return Control{-errno, -errno, -errno};
    }
    uc.pendingReads = openPendingReads(root).release();
    if (uc.pendingReads < 0) {
        return Control{-errno, -errno, -errno};
    }
    uc.logs = openLog(root).release();
    // logs may be absent, that's fine
    return uc;
}

static std::string makeCommandPath(std::string_view root, std::string_view item) {
    auto [itemRoot, subpath] = registry().rootAndSubpathFor(item);
    if (itemRoot != root) {
        return {};
    }
    // TODO: add "/.cmd/" if we decide to use a separate control tree.
    return path::join(itemRoot, subpath);
}

static void toString(IncFsFileId id, char* out) {
    // Make sure this function matches the one in the kernel (e.g. same case for a-f digits).
    static constexpr char kHexChar[] = "0123456789abcdef";

    for (auto item = std::begin(id.data); item != std::end(id.data); ++item, out += 2) {
        out[0] = kHexChar[(*item & 0xf0) >> 4];
        out[1] = kHexChar[(*item & 0x0f)];
    }
}

static std::string toStringImpl(IncFsFileId id) {
    std::string res(kIncFsFileIdStringLength, '\0');
    toString(id, res.data());
    return res;
}

static IncFsFileId toFileIdImpl(std::string_view str) {
    if (str.size() != kIncFsFileIdStringLength) {
        return kIncFsInvalidFileId;
    }

    IncFsFileId res;
    auto out = (char*)&res;
    for (auto it = str.begin(); it != str.end(); it += 2, ++out) {
        static const auto fromChar = [](char src) -> char {
            if (src >= '0' && src <= '9') {
                return src - '0';
            }
            if (src >= 'a' && src <= 'f') {
                return src - 'a' + 10;
            }
            return -1;
        };

        const char c[2] = {fromChar(it[0]), fromChar(it[1])};
        if (c[0] == -1 || c[1] == -1) {
            errno = EINVAL;
            return kIncFsInvalidFileId;
        }
        *out = (c[0] << 4) | c[1];
    }
    return res;
}

int IncFs_FileIdToString(IncFsFileId id, char* out) {
    if (!out) {
        return -EINVAL;
    }
    toString(id, out);
    return 0;
}

IncFsFileId IncFs_FileIdFromString(const char* in) {
    return toFileIdImpl({in, kIncFsFileIdStringLength});
}

IncFsFileId IncFs_FileIdFromMetadata(IncFsSpan metadata) {
    IncFsFileId id = {};
    if (size_t(metadata.size) <= sizeof(id)) {
        memcpy(&id, metadata.data, metadata.size);
    } else {
        uint8_t buffer[SHA_DIGEST_LENGTH];
        static_assert(sizeof(buffer) >= sizeof(id));

        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, metadata.data, metadata.size);
        SHA1_Final(buffer, &ctx);
        memcpy(&id, buffer, sizeof(id));
    }
    return id;
}

IncFsControl IncFs_Mount(const char* backingPath, const char* targetDir,
                         IncFsMountOptions options) {
    if (!init().enabledAndReady()) {
        LOG(WARNING) << "[incfs] Feature is not enabled";
        return {-ENOTSUP, -ENOTSUP, -ENOTSUP};
    }

    if (options.uidReadTimeoutCount > 0 && (readIncFsFeatures() & Features::uidTimeouts) == 0) {
        return {-ENOTSUP, -ENOTSUP, -ENOTSUP};
    }

    if (auto err = isValidMountTarget(targetDir); err != 0) {
        return {err, err, err};
    }
    if (!isAbsolute(backingPath)) {
        return {-EINVAL, -EINVAL, -EINVAL};
    }

    if (options.flags & createOnly) {
        if (const auto err = path::isEmptyDir(backingPath); err != 0) {
            return {err, err, err};
        }
    } else if (options.flags & android::incfs::truncate) {
        if (const auto err = rmDirContent(backingPath); err != 0) {
            return {err, err, err};
        }
    }

    const auto opts = makeMountOptionsString(options);
    if (::mount(backingPath, targetDir, INCFS_NAME, MS_NOSUID | MS_NODEV | MS_NOATIME,
                opts.c_str())) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] Failed to mount IncFS filesystem: " << targetDir;
        return {-error, -error, -error};
    }

    if (const auto err = selinux_android_restorecon(targetDir, SELINUX_ANDROID_RESTORECON_RECURSE);
        err != 0) {
        PLOG(ERROR) << "[incfs] Failed to restorecon: " << err;
        return {err, err, err};
    }

    registry().addRoot(targetDir);

    auto control = makeControl(targetDir);
    if (control.cmd < 0) {
        return std::move(control);
    }
    LOG(INFO) << "Opened control fd " << control.cmd << " " << fcntl(control.cmd, F_GETFD);
    return control.release();
}

IncFsControl IncFs_Open(const char* dir) {
    auto root = registry().rootFor(dir);
    if (root.empty()) {
        return {-EINVAL, -EINVAL, -EINVAL};
    }
    return makeControl(details::c_str(root)).release();
}

IncFsErrorCode IncFs_SetOptions(IncFsControl control, IncFsMountOptions options) {
    auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto opts = makeMountOptionsString(options);
    if (::mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOATIME,
                opts.c_str()) != 0) {
        const auto error = errno;
        PLOG(ERROR) << "[incfs] Failed to remount IncFS filesystem: " << root;
        return -error;
    }
    return 0;
}

IncFsErrorCode IncFs_Root(IncFsControl control, char buffer[], size_t* bufferSize) {
    std::string result = ::root(control.cmd);
    if (*bufferSize <= result.size()) {
        *bufferSize = result.size() + 1;
        return -EOVERFLOW;
    }
    result.copy(buffer, result.size());
    buffer[result.size()] = '\0';
    *bufferSize = result.size();
    return 0;
}

IncFsErrorCode IncFs_MakeFile(IncFsControl control, const char* path, int32_t mode, IncFsFileId id,
                              IncFsNewFileParams params) {
    auto [root, subpath] = registry().rootAndSubpathFor(path);
    if (root.empty()) {
        PLOG(WARNING) << "[incfs] makeFile failed for path " << path << ", root is empty.";
        return -EINVAL;
    }
    if (params.size < 0) {
        LOG(WARNING) << "[incfs] makeFile failed for path " << path
                     << ", size is invalid: " << params.size;
        return -ERANGE;
    }

    const auto [subdir, name] = path::splitDirBase(subpath);
    incfs_new_file_args args = {
            .size = (uint64_t)params.size,
            .mode = (uint16_t)mode,
            .directory_path = (uint64_t)subdir.data(),
            .file_name = (uint64_t)name.data(),
            .file_attr = (uint64_t)params.metadata.data,
            .file_attr_len = (uint32_t)params.metadata.size,
    };
    static_assert(sizeof(args.file_id.bytes) == sizeof(id.data));
    memcpy(args.file_id.bytes, id.data, sizeof(args.file_id.bytes));

    incfs_file_signature_info sigInfo = {};
    if (params.verification.hashAlgorithm != INCFS_HASH_NONE) {
        if (params.verification.rootHash.size < INCFS_MAX_HASH_SIZE) {
            return -EINVAL;
        }
        sigInfo.root_hash = (uint64_t)params.verification.rootHash.data;
        sigInfo.additional_data = (uint64_t)params.verification.additionalData.data;
        sigInfo.additional_data_size = (uint32_t)params.verification.additionalData.size;
        sigInfo.signature = (uint64_t)params.verification.signature.data;
        sigInfo.signature_size = (uint32_t)params.verification.signature.size;
        sigInfo.hash_tree_alg = params.verification.hashAlgorithm;
    }
    args.signature_info = (uint64_t)&sigInfo;

    if (::ioctl(control.cmd, INCFS_IOC_CREATE_FILE, &args)) {
        PLOG(WARNING) << "[incfs] makeFile failed for " << root << " / " << subdir << " / " << name
                      << " of " << params.size << " bytes";
        return -errno;
    }
    if (::chmod(path, mode)) {
        PLOG(WARNING) << "[incfs] couldn't change the file mode to 0" << std::oct << mode;
    }

    return 0;
}

IncFsErrorCode IncFs_MakeDir(IncFsControl control, const char* path, int32_t mode) {
    const auto root = ::root(control.cmd);
    if (root.empty()) {
        LOG(ERROR) << __func__ << "(): root is empty for " << path;
        return -EINVAL;
    }
    auto commandPath = makeCommandPath(root, path);
    if (commandPath.empty()) {
        LOG(ERROR) << __func__ << "(): commandPath is empty for " << path;
        return -EINVAL;
    }
    if (::mkdir(commandPath.c_str(), mode)) {
        PLOG(ERROR) << __func__ << "(): mkdir failed for " << commandPath;
        return -errno;
    }
    if (::chmod(path, mode)) {
        PLOG(WARNING) << "[incfs] couldn't change the directory mode to 0" << std::oct << mode;
    }

    return 0;
}

static IncFsErrorCode getMetadata(const char* path, char buffer[], size_t* bufferSize) {
    const auto res = ::getxattr(path, kMetadataAttrName, buffer, *bufferSize);
    if (res < 0) {
        if (errno == ERANGE) {
            auto neededSize = ::getxattr(path, kMetadataAttrName, buffer, 0);
            if (neededSize >= 0) {
                *bufferSize = neededSize;
                return 0;
            }
        }
        return -errno;
    }
    *bufferSize = res;
    return 0;
}

IncFsErrorCode IncFs_GetMetadataById(IncFsControl control, IncFsFileId fileId, char buffer[],
                                     size_t* bufferSize) {
    const auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto name = path::join(root, kIndexDir, toStringImpl(fileId));
    return getMetadata(details::c_str(name), buffer, bufferSize);
}

IncFsErrorCode IncFs_GetMetadataByPath(IncFsControl control, const char* path, char buffer[],
                                       size_t* bufferSize) {
    const auto pathRoot = registry().rootFor(path);
    const auto root = ::root(control.cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }

    return getMetadata(path, buffer, bufferSize);
}

IncFsFileId IncFs_GetId(IncFsControl control, const char* path) {
    const auto pathRoot = registry().rootFor(path);
    const auto root = ::root(control.cmd);
    if (root.empty() || root != pathRoot) {
        errno = EINVAL;
        return kIncFsInvalidFileId;
    }
    char buffer[kIncFsFileIdStringLength];
    const auto res = ::getxattr(path, kIdAttrName, buffer, sizeof(buffer));
    if (res != sizeof(buffer)) {
        return kIncFsInvalidFileId;
    }
    return toFileIdImpl({buffer, std::size(buffer)});
}

static IncFsErrorCode getSignature(int fd, char buffer[], size_t* bufferSize) {
    incfs_get_file_sig_args args = {
            .file_signature = (uint64_t)buffer,
            .file_signature_buf_size = (uint32_t)*bufferSize,
    };

    auto res = ::ioctl(fd, INCFS_IOC_READ_FILE_SIGNATURE, &args);
    if (res < 0) {
        if (errno == E2BIG) {
            *bufferSize = INCFS_MAX_SIGNATURE_SIZE;
        }
        return -errno;
    }
    *bufferSize = args.file_signature_len_out;
    return 0;
}

IncFsErrorCode IncFs_GetSignatureById(IncFsControl control, IncFsFileId fileId, char buffer[],
                                      size_t* bufferSize) {
    const auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto file = path::join(root, kIndexDir, toStringImpl(fileId));
    auto fd = openRaw(file);
    if (fd < 0) {
        return fd.get();
    }
    return getSignature(fd, buffer, bufferSize);
}

IncFsErrorCode IncFs_GetSignatureByPath(IncFsControl control, const char* path, char buffer[],
                                        size_t* bufferSize) {
    const auto pathRoot = registry().rootFor(path);
    const auto root = ::root(control.cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }
    return IncFs_UnsafeGetSignatureByPath(path, buffer, bufferSize);
}

IncFsErrorCode IncFs_UnsafeGetSignatureByPath(const char* path, char buffer[], size_t* bufferSize) {
    if (!isIncFsPath(path)) {
        return -EINVAL;
    }
    auto fd = openRaw(path);
    if (fd < 0) {
        return fd.get();
    }
    return getSignature(fd, buffer, bufferSize);
}

IncFsErrorCode IncFs_Link(IncFsControl control, const char* fromPath, const char* wherePath) {
    auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto cmdFrom = makeCommandPath(root, fromPath);
    if (cmdFrom.empty()) {
        return -EINVAL;
    }
    auto cmdWhere = makeCommandPath(root, wherePath);
    if (cmdWhere.empty()) {
        return -EINVAL;
    }
    if (::link(cmdFrom.c_str(), cmdWhere.c_str())) {
        return -errno;
    }
    return 0;
}

IncFsErrorCode IncFs_Unlink(IncFsControl control, const char* path) {
    auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto cmdPath = makeCommandPath(root, path);
    if (cmdPath.empty()) {
        return -EINVAL;
    }
    if (::unlink(cmdPath.c_str())) {
        if (errno == EISDIR) {
            if (!::rmdir(cmdPath.c_str())) {
                return 0;
            }
        }
        return -errno;
    }
    return 0;
}

static int waitForReads(int fd, int32_t timeoutMs, incfs_pending_read_info pendingReadsBuffer[],
                        size_t* pendingReadsBufferSize) {
    using namespace std::chrono;
    auto hrTimeout = steady_clock::duration(milliseconds(timeoutMs));

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

    auto res =
            ::read(fd, pendingReadsBuffer, *pendingReadsBufferSize * sizeof(*pendingReadsBuffer));
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

IncFsErrorCode IncFs_WaitForPendingReads(IncFsControl control, int32_t timeoutMs,
                                         IncFsReadInfo buffer[], size_t* bufferSize) {
    std::vector<incfs_pending_read_info> pendingReads;
    pendingReads.resize(*bufferSize);
    if (const auto res =
                waitForReads(control.pendingReads, timeoutMs, pendingReads.data(), bufferSize)) {
        return res;
    }
    for (size_t i = 0; i != *bufferSize; ++i) {
        buffer[i] = IncFsReadInfo{
                .bootClockTsUs = pendingReads[i].timestamp_us,
                .block = (IncFsBlockIndex)pendingReads[i].block_index,
                .serialNo = pendingReads[i].serial_number,
        };
        memcpy(&buffer[i].id.data, pendingReads[i].file_id.bytes, sizeof(buffer[i].id.data));
    }
    return 0;
}

IncFsErrorCode IncFs_WaitForPageReads(IncFsControl control, int32_t timeoutMs,
                                      IncFsReadInfo buffer[], size_t* bufferSize) {
    if (control.logs < 0) {
        return -EINVAL;
    }
    std::vector<incfs_pending_read_info> pendingReads;
    pendingReads.resize(*bufferSize);
    if (const auto res = waitForReads(control.logs, timeoutMs, pendingReads.data(), bufferSize)) {
        return res;
    }
    for (size_t i = 0; i != *bufferSize; ++i) {
        buffer[i] = IncFsReadInfo{
                .bootClockTsUs = pendingReads[i].timestamp_us,
                .block = (IncFsBlockIndex)pendingReads[i].block_index,
                .serialNo = pendingReads[i].serial_number,
        };
        memcpy(&buffer[i].id.data, pendingReads[i].file_id.bytes, sizeof(buffer[i].id.data));
    }
    return 0;
}

static IncFsFd openWrite(const char* path) {
    auto fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    return fd;
}

IncFsFd IncFs_OpenWriteByPath(IncFsControl control, const char* path) {
    const auto pathRoot = registry().rootFor(path);
    const auto root = ::root(control.cmd);
    if (root.empty() || root != pathRoot) {
        return -EINVAL;
    }
    return openWrite(makeCommandPath(root, path).c_str());
}

IncFsFd IncFs_OpenWriteById(IncFsControl control, IncFsFileId id) {
    const auto root = ::root(control.cmd);
    if (root.empty()) {
        return -EINVAL;
    }
    auto name = path::join(root, kIndexDir, toStringImpl(id));
    return openWrite(makeCommandPath(root, name).c_str());
}

static int writeBlocks(int fd, const incfs_new_data_block blocks[], int blocksCount) {
    if (fd < 0 || blocksCount == 0) {
        return 0;
    }
    if (blocksCount < 0) {
        return -EINVAL;
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

IncFsErrorCode IncFs_WriteBlocks(const IncFsDataBlock blocks[], size_t blocksCount) {
    incfs_new_data_block incfsBlocks[128];
    int writtenCount = 0;
    int incfsBlocksUsed = 0;
    int lastBlockFd = -1;
    for (size_t i = 0; i < blocksCount; ++i) {
        if (lastBlockFd != blocks[i].fileFd || incfsBlocksUsed == std::size(incfsBlocks)) {
            auto count = writeBlocks(lastBlockFd, incfsBlocks, incfsBlocksUsed);
            if (count > 0) {
                writtenCount += count;
            }
            if (count != incfsBlocksUsed) {
                return writtenCount ? writtenCount : count;
            }
            lastBlockFd = blocks[i].fileFd;
            incfsBlocksUsed = 0;
        }
        incfsBlocks[incfsBlocksUsed] = incfs_new_data_block{
                .block_index = (uint32_t)blocks[i].pageIndex,
                .data_len = blocks[i].dataSize,
                .data = (uint64_t)blocks[i].data,
                .compression = (uint8_t)blocks[i].compression,
                .flags = uint8_t(blocks[i].kind == INCFS_BLOCK_KIND_HASH ? INCFS_BLOCK_FLAGS_HASH
                                                                         : 0),
        };
        ++incfsBlocksUsed;
    }
    auto count = writeBlocks(lastBlockFd, incfsBlocks, incfsBlocksUsed);
    if (count > 0) {
        writtenCount += count;
    }
    return writtenCount ? writtenCount : count;
}

IncFsErrorCode IncFs_BindMount(const char* sourceDir, const char* targetDir) {
    if (!enabled()) {
        return -ENOTSUP;
    }

    auto [sourceRoot, subpath] = registry().rootAndSubpathFor(sourceDir);
    if (sourceRoot.empty()) {
        return -EINVAL;
    }
    if (subpath.empty()) {
        LOG(WARNING) << "[incfs] Binding the root mount '" << sourceRoot << "' is not allowed";
        return -EINVAL;
    }

    if (auto err = isValidMountTarget(targetDir); err != 0) {
        return err;
    }

    if (::mount(sourceDir, targetDir, nullptr, MS_BIND, nullptr)) {
        PLOG(ERROR) << "[incfs] Failed to bind mount '" << sourceDir << "' to '" << targetDir
                    << '\'';
        return -errno;
    }
    registry().addBind(sourceDir, targetDir);
    return 0;
}

IncFsErrorCode IncFs_Unmount(const char* dir) {
    if (!enabled()) {
        return -ENOTSUP;
    }

    registry().removeBind(dir);
    errno = 0;
    if (::umount2(dir, MNT_FORCE) == 0 || errno == EINVAL || errno == ENOENT) {
        // EINVAL - not a mount point, ENOENT - doesn't exist at all
        return -errno;
    }
    PLOG(WARNING) << __func__ << ": umount(force) failed, detaching '" << dir << '\'';
    errno = 0;
    if (!::umount2(dir, MNT_DETACH)) {
        return 0;
    }
    PLOG(WARNING) << __func__ << ": umount(detach) returned non-zero for '" << dir << '\'';
    return 0;
}

bool IncFs_IsIncFsPath(const char* path) {
    return isIncFsPath(path);
}
