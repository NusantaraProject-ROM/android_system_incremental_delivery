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

#ifndef ANDROID_INCREMENTAL_FILE_SYSTEM_DATA_LOADER_NDK_H
#define ANDROID_INCREMENTAL_FILE_SYSTEM_DATA_LOADER_NDK_H

#include <incfs_ndk.h>
#include <jni.h>

__BEGIN_DECLS

#define INCREMENTAL_DATALOADER_LIBRARY_NAME "libincremental_dataloader.so"

// Keep in sync with IncrementalConstants.java
typedef enum {
    INCREMENTAL_DATA_LOADER_SLOW_CONNECTION = 4,
    INCREMENTAL_DATA_LOADER_NO_CONNECTION = 5,
    INCREMENTAL_DATA_LOADER_CONNECTION_OK = 6,

    INCREMENTAL_DATA_LOADER_FIRST_STATUS = INCREMENTAL_DATA_LOADER_SLOW_CONNECTION,
    INCREMENTAL_DATA_LOADER_LAST_STATUS = INCREMENTAL_DATA_LOADER_CONNECTION_OK,
} IncrementalDataLoaderStatus;

typedef struct {
    const char* name;
    int fd;
} IncrementalNamedFd;

struct IncrementalDataLoaderParams {
    const char* staticArgs;
    const char* packageName;

    const IncrementalNamedFd* dynamicArgs;
    int dynamicArgsSize;
};

#ifdef __cplusplus

typedef class IncrementalFilesystemConnector {
} * IncrementalFilesystemConnectorPtr;
typedef class IncrementalStatusListener {
} * IncrementalStatusListenerPtr;

#else /* not __cplusplus */

typedef void* IncrementalFilesystemConnectorPtr;
typedef void* IncrementalStatusListenerPtr;

#endif /* not __cplusplus */

typedef JavaVM* IncrementalServiceVmPtr;
typedef jobject IncrementalServiceConnectorPtr;
typedef jobject IncrementalServiceParamsPtr;

struct IncrementalDataLoader {
    bool (*onStart)(struct IncrementalDataLoader* self);
    void (*onStop)(struct IncrementalDataLoader* self);
    void (*onDestroy)(struct IncrementalDataLoader* self);
    void (*onFileCreated)(struct IncrementalDataLoader* self, IncFsInode inode,
                          const char* metadataBytes, int metadataLength);

    void (*onPendingReads)(struct IncrementalDataLoader* self,
                           const IncFsPendingReadInfo pendingReads[], int pendingReadsCount);
    void (*onPageReads)(struct IncrementalDataLoader* self, const IncFsPageReadInfo pageReads[],
                        int pageReadsCount);
};

struct IncrementalDataLoaderFactory {
    struct IncrementalDataLoader* (*onCreate)(struct IncrementalDataLoaderFactory* self,
                                              const struct IncrementalDataLoaderParams*,
                                              IncrementalFilesystemConnectorPtr,
                                              IncrementalStatusListenerPtr, IncrementalServiceVmPtr,
                                              IncrementalServiceConnectorPtr,
                                              IncrementalServiceParamsPtr);
};
void Incremental_DataLoader_Initialize(struct IncrementalDataLoaderFactory*);

int Incremental_FilesystemConnector_writeBlocks(IncrementalFilesystemConnectorPtr,
                                                const struct incfs_new_data_block blocks[],
                                                int blocksCount);
// INCFS_MAX_FILE_ATTR_SIZE
int Incremental_FilesystemConnector_getRawMetadata(IncrementalFilesystemConnectorPtr,
                                                   IncFsInode ino, char buffer[],
                                                   size_t* bufferSize);

int Incremental_StatusListener_reportStatus(IncrementalStatusListenerPtr listener,
                                            IncrementalDataLoaderStatus status);

// DataLoaderService JNI
bool Incremental_DataLoaderService_OnCreate(JNIEnv* env, jobject service, jint storageId,
                                            jobject control, jobject params, jobject listener);
bool Incremental_DataLoaderService_OnStart(jint storageId);
bool Incremental_DataLoaderService_OnStop(jint storageId);
bool Incremental_DataLoaderService_OnDestroy(jint storageId);
bool Incremental_DataLoaderService_OnFileCreated(jint storageId, jlong inode, jbyteArray metadata);

__END_DECLS

#endif // ANDROID_INCREMENTAL_FILE_SYSTEM_DATA_LOADER_NDK_H
