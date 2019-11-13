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

#include "MountRegistry.h"
#include "incfs.h"
#include "path.h"
#include "split.h"

#include <android-base/logging.h>
#include <android-base/strings.h>

#include <charconv>
#include <fstream>
#include <unordered_map>

#include <limits.h>
#include <stdlib.h>

using namespace std::literals;

namespace android::incfs {

// /proc/self/mountinfo may have some special characters in paths replaced with their
// octal codes in the following pattern: '\xxx', e.g. \040 for space character.
// This function translates those patterns back into corresponding characters.
static void fixProcPath(std::string& path) {
    static const auto kPrefix = "\\"sv;
    static const auto kPatternLength = 4;
    auto pos = std::search(path.begin(), path.end(), kPrefix.begin(), kPrefix.end());
    if (pos == path.end()) {
        return;
    }
    auto dest = pos;
    do {
        if (path.end() - pos < kPatternLength || !std::equal(kPrefix.begin(), kPrefix.end(), pos)) {
            *dest++ = *pos++;
        } else {
            int charCode;
            auto res = std::from_chars(&*(pos + kPrefix.size()), &*(pos + kPatternLength), charCode,
                                       8);
            if (res.ec == std::errc{}) {
                *dest++ = char(charCode);
            } else {
                // Didn't convert, let's keep it as is.
                dest = std::copy(pos, pos + kPatternLength, dest);
                pos += kPatternLength;
            }
        }
    } while (pos != path.end());
    path.erase(dest, path.end());
}

MountRegistry::MountRegistry(std::string_view filesystem)
      : mFilesystem(filesystem.empty() ? INCFS_NAME : filesystem) {
    load();
}

std::string_view MountRegistry::rootFor(std::string_view path) const {
    auto [index, _] = rootIndex(path::normalize(path));
    if (index < 0) {
        return {};
    }
    return mRoots[index];
}

void MountRegistry::addRoot(std::string_view root) {
    const auto index = mRoots.size();
    auto absolute = path::normalize(root);
    auto it = mRootByBindPoint.insert_or_assign(absolute, index).first;
    mRootBinds.push_back({it});
    mRoots.emplace_back(std::move(absolute));
}

void MountRegistry::removeRoot(std::string_view root) {
    auto absolute = path::normalize(root);
    auto it = mRootByBindPoint.find(absolute);
    if (it == mRootByBindPoint.end()) {
        LOG(WARNING) << "[incfs] Trying to remove non-existent root '" << root << '\'';
        return;
    }
    const auto index = it->second;
    if (index >= int(mRoots.size())) {
        LOG(ERROR) << "[incfs] Root '" << root << "' has index " << index
                   << " out of bounds (total roots count is " << mRoots.size();
        return;
    }

    if (index + 1 == int(mRoots.size())) {
        mRoots.pop_back();
        mRootBinds.pop_back();
        // Run a small GC job here as we may be able to remove some obsolete
        // entries.
        while (mRoots.back().empty()) {
            mRoots.pop_back();
            mRootBinds.pop_back();
        }
    } else {
        mRoots[index].clear();
        mRoots[index].shrink_to_fit();
        mRootBinds[index].clear();
        mRootBinds[index].shrink_to_fit();
    }
    mRootByBindPoint.erase(it);
}

void MountRegistry::addBind(std::string_view what, std::string_view where) {
    auto [root, _] = rootIndex(path::normalize(what));
    if (root < 0) {
        LOG(ERROR) << "[incfs] No root found for bind from " << what << " to " << where;
        return;
    }
    auto it = mRootByBindPoint.insert_or_assign(path::normalize(where), root).first;
    mRootBinds[root].push_back(it);
}

void MountRegistry::moveBind(std::string_view src, std::string_view dest) {
    auto [root, rootIt] = rootIndex(path::normalize(src));
    if (root < 0) {
        LOG(ERROR) << "[incfs] No root found for bind move from " << src << " to " << dest;
        return;
    }

    mRootByBindPoint.erase(rootIt);
    auto destAbsolute = path::normalize(dest);
    rootIt = mRootByBindPoint.insert_or_assign(destAbsolute, root).first;
    auto bindIt = std::find(mRootBinds[root].begin(), mRootBinds[root].end(), rootIt);
    *bindIt = rootIt;
    if (mRoots[root] == src) {
        // moving the whole root
        mRoots[root] = std::move(destAbsolute);
    }
}

void MountRegistry::removeBind(std::string_view what) {
    auto absolute = path::normalize(what);
    auto [root, rootIt] = rootIndex(absolute);
    if (root < 0) {
        LOG(WARNING) << "[incfs] Trying to remove non-existent bind point '" << what << '\'';
        return;
    }
    if (mRoots[root] == absolute) {
        removeRoot(absolute);
        return;
    }

    mRootByBindPoint.erase(rootIt);
    auto itBind = std::find(mRootBinds[root].begin(), mRootBinds[root].end(), rootIt);
    std::swap(mRootBinds[root].back(), *itBind);
    mRootBinds[root].pop_back();
}

void MountRegistry::clear() {
    mRootByBindPoint.clear();
    mRootBinds.clear();
    mRoots.clear();
}

void MountRegistry::load() {
    std::ifstream in("/proc/self/mountinfo"sv);
    std::string line;

    struct MountInfo {
        std::string root;
        std::vector<std::string> bindPoints;
    };
    std::unordered_map<std::string, MountInfo> mountsByGroup;

    while (getline(in, line)) {
        auto items = Split(line, ' ');
        if (items.size() < 10) {
            LOG(WARNING) << "[incfs] bad line in mountinfo: |" << line << '|';
            continue;
        }
        const auto name = items.rbegin()[2];
        if (!base::StartsWith(name, mFilesystem)) {
            continue;
        }
        const auto groupId = items[2];
        const auto subdir = items[3];
        auto mountPoint = std::string(items[4]);
        fixProcPath(mountPoint);
        auto& mount = mountsByGroup[std::string(groupId)];
        if (subdir == "/"sv) {
            mount.root.assign(mountPoint);
        }
        mount.bindPoints.emplace_back(std::move(mountPoint));
    }

    for (auto& [group, mount] : mountsByGroup) {
        const auto index = mRoots.size();
        std::vector<BindMap::const_iterator> binds;
        binds.reserve(mount.bindPoints.size());
        for (auto& bind : mount.bindPoints) {
            auto it = mRootByBindPoint.insert_or_assign(std::move(bind), index).first;
            binds.push_back(it);
        }
        mRoots.emplace_back(std::move(mount.root));
        mRootBinds.emplace_back(std::move(binds));
    }

    LOG(INFO) << "[incfs] Found " << mRoots.size() << ' ' << mFilesystem
              << " instances with total of " << mRootByBindPoint.size() << " mount points";
    if (base::VERBOSE >= base::GetMinimumLogSeverity()) {
        auto index = 0;
        for (auto&& root : mRoots) {
            LOG(INFO) << "[incfs]    '" << root << '\'';
            for (auto&& bind : mRootBinds[index]) {
                LOG(INFO) << "[incfs]      : '" << bind->first << '\'';
            }
            ++index;
        }
    }
}

std::pair<int, MountRegistry::BindMap::const_iterator> MountRegistry::rootIndex(
        std::string_view path) const {
    auto it = mRootByBindPoint.lower_bound(path);
    if (it != mRootByBindPoint.end() && it->first == path) {
        return {it->second, it};
    }
    if (it != mRootByBindPoint.begin()) {
        --it;
        if (base::StartsWith(path, it->first) && path.size() > it->first.size() &&
            path[it->first.size()] == '/') {
            const auto index = it->second;
            if (index >= int(mRoots.size()) || mRoots[index].empty()) {
                LOG(ERROR) << "[incfs] Root for path '" << path << "' #" << index
                           << " is not valid";
                return {-1, {}};
            }
            return {index, it};
        }
    }
    return {-1, {}};
}

} // namespace android::incfs
