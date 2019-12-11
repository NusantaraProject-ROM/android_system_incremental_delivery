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

#include "dataloader.h"

namespace android::dataloader {
namespace details {

struct DataLoaderImpl : public ::DataLoader {
    DataLoaderImpl(DataLoaderPtr&& dataLoader) : mDataLoader(std::move(dataLoader)) {
        onStart = [](DataLoader* self) -> bool {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onStart();
        };
        onStop = [](DataLoader* self) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onStop();
        };
        onDestroy = [](DataLoader* self) {
            auto me = static_cast<DataLoaderImpl*>(self);
            me->mDataLoader->onDestroy();
            delete me;
        };
        onPendingReads = [](DataLoader* self, const IncFsPendingReadInfo pendingReads[],
                            int pendingReadsCount) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onPendingReads(
                    PendingReads(pendingReads, pendingReadsCount));
        };
        onPageReads = [](DataLoader* self, const IncFsPageReadInfo pageReads[],
                         int pageReadsCount) {
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onPageReads(
                    PageReads(pageReads, pageReadsCount));
        };
        onFileCreated = [](DataLoader* self, Inode inode, const char* metadataBytes,
                           int metadataLength) {
            RawMetadata metadata(metadataBytes, metadataBytes + metadataLength);
            return static_cast<DataLoaderImpl*>(self)->mDataLoader->onFileCreated(inode, metadata);
        };
    }

private:
    DataLoaderPtr mDataLoader;
};

inline DataLoaderParams createParams(const ::DataLoaderParams* params) {
    std::string staticArgs(params->staticArgs);
    std::string packageName(params->packageName);
    std::vector<DataLoaderParams::NamedFd> dynamicArgs(params->dynamicArgsSize);
    for (size_t i = 0; i < dynamicArgs.size(); ++i) {
        dynamicArgs[i].name = params->dynamicArgs[i].name;
        dynamicArgs[i].fd = params->dynamicArgs[i].fd;
    }
    return DataLoaderParams(std::move(staticArgs), std::move(packageName), std::move(dynamicArgs));
}

struct DataLoaderFactoryImpl : public ::DataLoaderFactory {
    DataLoaderFactoryImpl(DataLoader::Factory&& factory) : mFactory(factory) {
        onCreate = [](::DataLoaderFactory* self, const ::DataLoaderParams* params,
                      ::DataLoaderFilesystemConnectorPtr fsConnector,
                      ::DataLoaderStatusListenerPtr statusListener, ::DataLoaderServiceVmPtr vm,
                      ::DataLoaderServiceConnectorPtr serviceConnector,
                      ::DataLoaderServiceParamsPtr serviceParams) {
            auto me = static_cast<DataLoaderFactoryImpl*>(self);
            ::DataLoader* result = nullptr;
            auto dataLoader = me->mFactory(vm);
            if (!dataLoader ||
                !dataLoader->onCreate(createParams(params),
                                      static_cast<FilesystemConnector*>(fsConnector),
                                      static_cast<StatusListener*>(statusListener),
                                      serviceConnector, serviceParams)) {
                return result;
            }
            result = new DataLoaderImpl(std::move(dataLoader));
            return result;
        };
    }

private:
    DataLoader::Factory mFactory;
};

} // namespace details

inline void DataLoader::initialize(DataLoader::Factory&& factory) {
    DataLoader_Initialize(new details::DataLoaderFactoryImpl(std::move(factory)));
}

inline DataLoaderParams::DataLoaderParams(std::string&& staticArgs, std::string&& packageName,
                                          std::vector<NamedFd>&& dynamicArgs)
      : mStaticArgs(std::move(staticArgs)),
        mPackageName(std::move(packageName)),
        mDynamicArgs(std::move(dynamicArgs)) {}

inline int FilesystemConnector::writeBlocks(const incfs_new_data_block blocks[], int blocksCount) {
    return DataLoader_FilesystemConnector_writeBlocks(this, blocks, blocksCount);
}

inline RawMetadata FilesystemConnector::getRawMetadata(Inode ino) {
    RawMetadata metadata(INCFS_MAX_FILE_ATTR_SIZE);
    size_t size = metadata.size();
    if (DataLoader_FilesystemConnector_getRawMetadata(this, ino, metadata.data(), &size) < 0) {
        return {};
    }
    metadata.resize(size);
    return metadata;
}

inline bool StatusListener::reportStatus(DataLoaderStatus status) {
    return DataLoader_StatusListener_reportStatus(this, status);
}

} // namespace android::dataloader
