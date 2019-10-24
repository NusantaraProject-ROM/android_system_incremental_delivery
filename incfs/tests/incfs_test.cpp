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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <sys/select.h>
#include <unistd.h>

#include <thread>

#include "incfs.h"

using namespace android::incfs;

static bool exists(std::string_view path) {
    return access(path.data(), F_OK) == 0;
}

class IncFsTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        TemporaryDir tmp_dir_for_mount, tmp_dir_for_image;
        mount_dir_path_ = tmp_dir_for_mount.path;
        image_dir_path_ = tmp_dir_for_image.path;
        image_path_ = image_dir_path_ + "/image.img";
        if (!enabled()) {
            GTEST_SKIP() << "incfs test not supported";
        } else {
            control_ = mount(image_path_, mount_dir_path_, 0, kDefaultReadTimeout);
            ASSERT_TRUE(control_.cmdFd >= 0);
            ASSERT_TRUE(control_.logFd >= 0);
            tmp_dir_for_mount.DoNotRemove();
            tmp_dir_for_image.DoNotRemove();
        }
    }
    virtual void TearDown() {
        if (control_.cmdFd >= 0) {
            unmount(mount_dir_path_);
        }
        android::base::RemoveFileIfExists(image_path_, nullptr);
        ::rmdir(image_dir_path_.c_str());
        ::rmdir(mount_dir_path_.c_str());
        ASSERT_FALSE(exists(image_dir_path_));
        ASSERT_FALSE(exists(mount_dir_path_));
    }
    std::string image_path_;
    std::string image_dir_path_;
    std::string mount_dir_path_;
    const std::string test_file_name_ = "test.txt";
    const std::string test_dir_name_ = "test_dir";
    const int test_file_size_ = INCFS_DATA_FILE_BLOCK_SIZE;
    IncFsControl control_;
};

TEST_F(IncFsTest, GetIncfsVersion) {
    // if incfs is enabled, version should be >= 0.
    ASSERT_GE(version(), 0);
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
    ASSERT_EQ(0, bindMount(mount_dir_path_, tmp_dir_to_bind.path));
    ASSERT_TRUE(isIncFsPath(tmp_dir_to_bind.path));
}

TEST_F(IncFsTest, BindMount) {
    TemporaryDir tmp_dir_to_bind;
    ASSERT_EQ(0, bindMount(mount_dir_path_, tmp_dir_to_bind.path));
    ASSERT_TRUE(makeFile(control_, test_file_name_, INCFS_ROOT_INODE, test_file_size_, {}) > 0);
    const auto file_binded_path = std::string(tmp_dir_to_bind.path) + "/" + test_file_name_;
    ASSERT_TRUE(exists(file_binded_path.c_str()));
}

TEST_F(IncFsTest, Root) {
    ASSERT_EQ(mount_dir_path_, root(control_));
}

TEST_F(IncFsTest, Open) {
    IncFsControl control = open(mount_dir_path_);
    ASSERT_TRUE(control.cmdFd >= 0);
    ASSERT_TRUE(control.logFd >= 0);
}

TEST_F(IncFsTest, OpenFail) {
    TemporaryDir tmp_dir_to_bind;
    IncFsControl control = open(tmp_dir_to_bind.path);
    ASSERT_TRUE(control.cmdFd < 0);
    ASSERT_TRUE(control.logFd < 0);
}

TEST_F(IncFsTest, MakeDir) {
    const auto dir_path = mount_dir_path_ + "/" + test_dir_name_;
    ASSERT_FALSE(exists(dir_path));
    ASSERT_TRUE(makeDir(control_, test_dir_name_, INCFS_ROOT_INODE, {}) > 0);
    ASSERT_TRUE(exists(dir_path));
}

TEST_F(IncFsTest, MakeFile) {
    const int dir_ino = makeDir(control_, test_dir_name_, INCFS_ROOT_INODE, {});
    ASSERT_TRUE(dir_ino > 0);
    const auto file_path = mount_dir_path_ + "/" + test_dir_name_ + "/" + test_file_name_;
    ASSERT_FALSE(exists(file_path));
    ASSERT_TRUE(makeFile(control_, test_file_name_, dir_ino, test_file_size_, {}) > 0);
    struct stat s;
    ASSERT_EQ(0, stat(file_path.data(), &s));
    ASSERT_EQ(test_file_size_, (int)s.st_size);
}

TEST_F(IncFsTest, GetMetaData) {
    const std::string metadata = "abc";
    const int file_ino =
            makeFile(control_, test_file_name_, INCFS_ROOT_INODE, test_file_size_, metadata);
    const auto raw_metadata = getMetadata(control_, file_ino);
    const std::string result(raw_metadata.begin(), raw_metadata.end());
    ASSERT_EQ(metadata, result);
}

TEST_F(IncFsTest, LinkAndUnlink) {
    const int file_ino = makeFile(control_, test_file_name_, INCFS_ROOT_INODE, test_file_size_, {});
    const int dir_ino = makeDir(control_, test_dir_name_, INCFS_ROOT_INODE, {});
    const std::string test_file = "test1.txt";
    const auto linked_file_path = mount_dir_path_ + "/" + test_dir_name_ + "/" + test_file;
    ASSERT_FALSE(exists(linked_file_path));
    ASSERT_EQ(0, link(control_, file_ino, dir_ino, test_file));
    ASSERT_TRUE(exists(linked_file_path));
    ASSERT_EQ(0, unlink(control_, dir_ino, test_file));
    ASSERT_FALSE(exists(linked_file_path));
}

TEST_F(IncFsTest, WriteBlocksAndPageRead) {
    ASSERT_TRUE(control_.logFd > 0);
    const int file_ino = makeFile(control_, test_file_name_, INCFS_ROOT_INODE, test_file_size_, {});
    std::vector<uint8_t> data(INCFS_DATA_FILE_BLOCK_SIZE);
    const auto inst = incfs_new_data_block{.file_ino = static_cast<uint64_t>(file_ino),
                                           .block_index = static_cast<uint32_t>(0),
                                           .data_len = static_cast<uint32_t>(data.size()),
                                           .data = reinterpret_cast<uint64_t>(data.data()),
                                           .compression = static_cast<uint8_t>(COMPRESSION_NONE)};
    ASSERT_TRUE(writeBlocks(control_, &inst, 1) > 0);

    std::thread wait_page_read_thread([&]() {
        std::vector<PageReadInfo> reads;
        int count_to_timeout = 0;
        while (true) {
            if (WaitResult::HaveData ==
                waitForPageReads(control_, std::chrono::milliseconds(0), &reads)) {
                break;
            }
            sleep(1);
            count_to_timeout++;
            if (count_to_timeout == 5) {
                break;
            }
        }
        ASSERT_FALSE(reads.empty());
        ASSERT_EQ(file_ino, static_cast<int>(reads[0].file_ino));
        ASSERT_EQ(0, static_cast<int>(reads[0].block_index));
    });

    const auto file_path = mount_dir_path_ + "/" + test_file_name_;
    const android::base::unique_fd fd(open(file_path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
    ASSERT_TRUE(fd >= 0);
    char buf[INCFS_DATA_FILE_BLOCK_SIZE];
    ASSERT_TRUE(android::base::ReadFully(fd, buf, sizeof(buf)));
    wait_page_read_thread.join();
}

TEST_F(IncFsTest, WaitForPendingReads) {
    ASSERT_TRUE(control_.cmdFd > 0);
    const int file_ino = makeFile(control_, test_file_name_, INCFS_ROOT_INODE, test_file_size_, {});
    ASSERT_TRUE(file_ino >= 0);

    std::thread wait_pending_read_thread([&]() {
        std::vector<PendingReadInfo> pending_reads;
        int count_to_timeout = 0;
        while (true) {
            if (WaitResult::HaveData ==
                waitForPendingReads(control_, std::chrono::milliseconds(0), &pending_reads)) {
                break;
            }
            sleep(1);
            count_to_timeout++;
            if (count_to_timeout == 5) {
                break;
            }
        }
        ASSERT_FALSE(pending_reads.empty());
        ASSERT_EQ(file_ino, static_cast<int>(pending_reads[0].file_ino));
        ASSERT_EQ(0, static_cast<int>(pending_reads[0].block_index));
    });

    const auto file_path = mount_dir_path_ + "/" + test_file_name_;
    const android::base::unique_fd fd(open(file_path.c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
    ASSERT_TRUE(fd >= 0);
    char buf[INCFS_DATA_FILE_BLOCK_SIZE];
    ASSERT_FALSE(android::base::ReadFully(fd, buf, sizeof(buf)));
    wait_pending_read_thread.join();
}
