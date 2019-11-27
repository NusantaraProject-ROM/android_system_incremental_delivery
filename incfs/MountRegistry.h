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

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace android::incfs {

//
// MountRegistry - a collection of mount points for a particular filesystem, with
//      live tracking of binds, mounts and unmounts on it
//

class MountRegistry {
public:
    MountRegistry(std::string_view filesystem = {});

    const std::vector<std::string>& roots() const { return mRoots; }
    std::string_view rootFor(std::string_view path) const;
    std::pair<std::string_view, std::string> rootAndSubpathFor(std::string_view path) const;

    void addRoot(std::string_view root);
    void removeRoot(std::string_view root);

    void addBind(std::string_view what, std::string_view where);
    void moveBind(std::string_view src, std::string_view dest);
    void removeBind(std::string_view what);

    void reload() {
        clear();
        load();
    }

private:
    // std::less<> enables heterogeneous lookups, e.g. by a string_view
    using BindMap = std::map<std::string, std::pair<std::string, int>, std::less<>>;

    void clear();
    void load();
    std::pair<int, BindMap::const_iterator> rootIndex(std::string_view path) const;
    std::pair<int, BindMap::const_iterator> rootIndexImpl(std::string_view path) const;

    std::string mFilesystem;
    std::vector<std::string> mRoots;
    std::vector<std::vector<BindMap::const_iterator>> mRootBinds;
    BindMap mRootByBindPoint;
};

} // namespace android::incfs
