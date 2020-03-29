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
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <selinux/selinux.h>
#include <sys/select.h>
#include <unistd.h>

#include <optional>
#include <thread>

#include "path.h"

using namespace android::incfs;
using namespace std::literals;

static bool exists(std::string_view path) {
    return access(path.data(), F_OK) == 0;
}

struct ScopedUnmount {
    std::string path_;
    explicit ScopedUnmount(std::string&& path) : path_(std::move(path)) {}
    ~ScopedUnmount() { unmount(path_); }
};

class IncFsTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        tmp_dir_for_mount_.emplace();
        mount_dir_path_ = tmp_dir_for_mount_->path;
        tmp_dir_for_image_.emplace();
        image_dir_path_ = tmp_dir_for_image_->path;
        ASSERT_TRUE(exists(image_dir_path_));
        ASSERT_TRUE(exists(mount_dir_path_));
        if (!enabled()) {
            GTEST_SKIP() << "test not supported: IncFS is not enabled";
        } else {
            control_ =
                    mount(image_dir_path_, mount_dir_path_,
                          MountOptions{.readLogBufferPages = 4,
                                       .defaultReadTimeoutMs = std::chrono::duration_cast<
                                                                       std::chrono::milliseconds>(
                                                                       kDefaultReadTimeout)
                                                                       .count()});
            ASSERT_TRUE(control_.cmd() >= 0) << "Expected >= 0 got " << control_.cmd();
            ASSERT_TRUE(control_.pendingReads() >= 0);
            ASSERT_TRUE(control_.logs() >= 0);
            checkRestoreconResult(mountPath(INCFS_PENDING_READS_FILENAME));
            checkRestoreconResult(mountPath(INCFS_LOG_FILENAME));
        }
    }

    static void checkRestoreconResult(std::string_view path) {
        char* ctx = nullptr;
        ASSERT_NE(-1, getfilecon(path.data(), &ctx));
        ASSERT_EQ("u:object_r:shell_data_file:s0", std::string(ctx));
        freecon(ctx);
    }

    virtual void TearDown() {
        unmount(mount_dir_path_);
        tmp_dir_for_image_.reset();
        tmp_dir_for_mount_.reset();
        EXPECT_FALSE(exists(image_dir_path_));
        EXPECT_FALSE(exists(mount_dir_path_));
    }

    template <class... Paths>
    std::string mountPath(Paths&&... paths) const {
        return path::join(mount_dir_path_, std::forward<Paths>(paths)...);
    }

    static IncFsFileId fileId(uint64_t i) {
        IncFsFileId id = {};
        static_assert(sizeof(id) >= sizeof(i));
        memcpy(&id, &i, sizeof(i));
        return id;
    }

    static IncFsSpan metadata(std::string_view sv) {
        return {.data = sv.data(), .size = IncFsSize(sv.size())};
    }

    std::string mount_dir_path_;
    std::optional<TemporaryDir> tmp_dir_for_mount_;
    std::string image_dir_path_;
    std::optional<TemporaryDir> tmp_dir_for_image_;
    inline static const std::string_view test_file_name_ = "test.txt"sv;
    inline static const std::string_view test_dir_name_ = "test_dir"sv;
    inline static const int test_file_size_ = INCFS_DATA_FILE_BLOCK_SIZE;
    Control control_;
};

TEST_F(IncFsTest, GetIncfsFeatures) {
    ASSERT_NE(features(), none);
}

TEST_F(IncFsTest, FalseIncfsPath) {
    TemporaryDir test_dir;
    ASSERT_FALSE(isIncFsPath(test_dir.path));
}

TEST_F(IncFsTest, TrueIncfsPath) {
    ASSERT_TRUE(isIncFsPath(mount_dir_path_));
}

TEST_F(IncFsTest, TrueIncfsPathForBindMount) {
    TemporaryDir tmp_dir_to_bind;
    ASSERT_EQ(0, makeDir(control_, mountPath(test_dir_name_)));
    ASSERT_EQ(0, bindMount(mountPath(test_dir_name_), tmp_dir_to_bind.path));
    ScopedUnmount su(tmp_dir_to_bind.path);
    ASSERT_TRUE(isIncFsPath(tmp_dir_to_bind.path));
}

TEST_F(IncFsTest, MakeDir) {
    const auto dir_path = mountPath(test_dir_name_);
    ASSERT_FALSE(exists(dir_path));
    ASSERT_GE(makeDir(control_, dir_path), 0);
    ASSERT_TRUE(exists(dir_path));
}

TEST_F(IncFsTest, BindMount) {
    {
        TemporaryDir tmp_dir_to_bind;
        ASSERT_EQ(0, makeDir(control_, mountPath(test_dir_name_)));
        ASSERT_EQ(0, bindMount(mountPath(test_dir_name_), tmp_dir_to_bind.path));
        ScopedUnmount su(tmp_dir_to_bind.path);
        const auto test_file = mountPath(test_dir_name_, test_file_name_);
        ASSERT_FALSE(exists(test_file.c_str())) << "Present: " << test_file;
        ASSERT_EQ(0,
                  makeFile(control_, test_file, 0555, fileId(1),
                           {.size = test_file_size_, .metadata = metadata("md")}));
        ASSERT_TRUE(exists(test_file.c_str())) << "Missing: " << test_file;
        const auto file_binded_path = path::join(tmp_dir_to_bind.path, test_file_name_);
        ASSERT_TRUE(exists(file_binded_path.c_str())) << "Missing: " << file_binded_path;
    }

    {
        // Don't allow binding the root
        TemporaryDir tmp_dir_to_bind;
        ASSERT_EQ(-EINVAL, bindMount(mount_dir_path_, tmp_dir_to_bind.path));
    }
}

TEST_F(IncFsTest, Root) {
    ASSERT_EQ(mount_dir_path_, root(control_)) << "Error: " << errno;
}

TEST_F(IncFsTest, Open) {
    Control control = open(mount_dir_path_);
    ASSERT_TRUE(control.cmd() >= 0);
    ASSERT_TRUE(control.pendingReads() >= 0);
    ASSERT_TRUE(control.logs() >= 0);
}

TEST_F(IncFsTest, OpenFail) {
    TemporaryDir tmp_dir_to_bind;
    Control control = open(tmp_dir_to_bind.path);
    ASSERT_TRUE(control.cmd() < 0);
    ASSERT_TRUE(control.pendingReads() < 0);
    ASSERT_TRUE(control.logs() < 0);
}

TEST_F(IncFsTest, MakeFile) {
    ASSERT_EQ(0, makeDir(control_, mountPath(test_dir_name_)));
    const auto file_path = mountPath(test_dir_name_, test_file_name_);
    ASSERT_FALSE(exists(file_path));
    ASSERT_EQ(0,
              makeFile(control_, file_path, 0111, fileId(1),
                       {.size = test_file_size_, .metadata = metadata("md")}));
    struct stat s;
    ASSERT_EQ(0, stat(file_path.c_str(), &s));
    ASSERT_EQ(test_file_size_, (int)s.st_size);
}

TEST_F(IncFsTest, MakeFile0) {
    ASSERT_EQ(0, makeDir(control_, mountPath(test_dir_name_)));
    const auto file_path = mountPath(test_dir_name_, ".info");
    ASSERT_FALSE(exists(file_path));
    ASSERT_EQ(0,
              makeFile(control_, file_path, 0555, fileId(1),
                       {.size = 0, .metadata = metadata("mdsdfhjasdkfas l;jflaskdjf")}));
    struct stat s;
    ASSERT_EQ(0, stat(file_path.c_str(), &s));
    ASSERT_EQ(0, (int)s.st_size);
}

TEST_F(IncFsTest, GetFileId) {
    auto id = fileId(1);
    ASSERT_EQ(0,
              makeFile(control_, mountPath(test_file_name_), 0555, id,
                       {.size = test_file_size_, .metadata = metadata("md")}));
    EXPECT_EQ(id, getFileId(control_, mountPath(test_file_name_))) << "errno = " << errno;
    EXPECT_EQ(kIncFsInvalidFileId, getFileId(control_, test_file_name_));
    EXPECT_EQ(kIncFsInvalidFileId, getFileId(control_, "asdf"));
    EXPECT_EQ(kIncFsInvalidFileId, getFileId({}, mountPath(test_file_name_)));
}

TEST_F(IncFsTest, GetMetaData) {
    const std::string_view md = "abc"sv;
    ASSERT_EQ(0,
              makeFile(control_, mountPath(test_file_name_), 0555, fileId(1),
                       {.size = test_file_size_, .metadata = metadata(md)}));
    {
        const auto raw_metadata = getMetadata(control_, mountPath(test_file_name_));
        ASSERT_NE(0u, raw_metadata.size()) << errno;
        const std::string result(raw_metadata.begin(), raw_metadata.end());
        ASSERT_EQ(md, result);
    }
    {
        const auto raw_metadata = getMetadata(control_, fileId(1));
        ASSERT_NE(0u, raw_metadata.size()) << errno;
        const std::string result(raw_metadata.begin(), raw_metadata.end());
        ASSERT_EQ(md, result);
    }
}

TEST_F(IncFsTest, LinkAndUnlink) {
    ASSERT_EQ(0, makeFile(control_, mountPath(test_file_name_), 0555, fileId(1), {.size = 0}));
    ASSERT_EQ(0, makeDir(control_, mountPath(test_dir_name_)));
    const std::string_view test_file = "test1.txt"sv;
    const auto linked_file_path = mountPath(test_dir_name_, test_file);
    ASSERT_FALSE(exists(linked_file_path));
    ASSERT_EQ(0, link(control_, mountPath(test_file_name_), linked_file_path));
    ASSERT_TRUE(exists(linked_file_path));
    ASSERT_EQ(0, unlink(control_, linked_file_path));
    ASSERT_FALSE(exists(linked_file_path));
}

TEST_F(IncFsTest, WriteBlocksAndPageRead) {
    const auto id = fileId(1);
    ASSERT_TRUE(control_.logs() >= 0);
    ASSERT_EQ(0,
              makeFile(control_, mountPath(test_file_name_), 0555, id, {.size = test_file_size_}));
    auto fd = openWrite(control_, fileId(1));
    ASSERT_GE(fd, 0);

    std::vector<char> data(INCFS_DATA_FILE_BLOCK_SIZE);
    auto block = DataBlock{
            .fileFd = fd,
            .pageIndex = 0,
            .compression = INCFS_COMPRESSION_KIND_NONE,
            .dataSize = (uint32_t)data.size(),
            .data = data.data(),
    };
    ASSERT_EQ(1, writeBlocks({&block, 1}));

    std::thread wait_page_read_thread([&]() {
        std::vector<ReadInfo> reads;
        ASSERT_EQ(WaitResult::HaveData,
                  waitForPageReads(control_, std::chrono::seconds(5), &reads));
        ASSERT_FALSE(reads.empty());
        ASSERT_EQ(0, memcmp(&id, &reads[0].id, sizeof(id)));
        ASSERT_EQ(0, int(reads[0].block));
    });

    const auto file_path = mountPath(test_file_name_);
    const android::base::unique_fd readFd(open(file_path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
    ASSERT_TRUE(readFd >= 0);
    char buf[INCFS_DATA_FILE_BLOCK_SIZE];
    ASSERT_TRUE(android::base::ReadFully(readFd, buf, sizeof(buf)));
    wait_page_read_thread.join();
}

TEST_F(IncFsTest, WaitForPendingReads) {
    const auto id = fileId(1);
    ASSERT_EQ(0,
              makeFile(control_, mountPath(test_file_name_), 0555, id, {.size = test_file_size_}));

    std::thread wait_pending_read_thread([&]() {
        std::vector<ReadInfo> pending_reads;
        ASSERT_EQ(WaitResult::HaveData,
                  waitForPendingReads(control_, std::chrono::seconds(10), &pending_reads));
        ASSERT_GT(pending_reads.size(), 0u);
        ASSERT_EQ(0, memcmp(&id, &pending_reads[0].id, sizeof(id)));
        ASSERT_EQ(0, (int)pending_reads[0].block);

        auto fd = openWrite(control_, fileId(1));
        ASSERT_GE(fd, 0);

        std::vector<char> data(INCFS_DATA_FILE_BLOCK_SIZE);
        auto block = DataBlock{
                .fileFd = fd,
                .pageIndex = 0,
                .compression = INCFS_COMPRESSION_KIND_NONE,
                .dataSize = (uint32_t)data.size(),
                .data = data.data(),
        };
        ASSERT_EQ(1, writeBlocks({&block, 1}));
    });

    const auto file_path = mountPath(test_file_name_);
    const android::base::unique_fd fd(open(file_path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
    ASSERT_GE(fd.get(), 0);
    char buf[INCFS_DATA_FILE_BLOCK_SIZE];
    ASSERT_TRUE(android::base::ReadFully(fd, buf, sizeof(buf)));
    wait_pending_read_thread.join();
}
