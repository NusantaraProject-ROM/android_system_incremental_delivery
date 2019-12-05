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
#define LOG_TAG "incfs-manageddataloader"

#include "ManagedDataLoader.h"

#include <android-base/logging.h>

#include "JNIHelpers.h"

namespace android::incremental {

namespace {

struct JniIds {
    jmethodID parcelFileDescriptorDup;
    jmethodID parcelFileDescriptorGetFileDescriptor;

    jclass incrementalFileSystemConnector;
    jmethodID incrementalFileSystemConnectorConstruct;

    jclass statusListener;
    jmethodID statusListenerConstruct;

    jclass dataLoaderParams;
    jmethodID dataLoaderParamsCtor;

    jmethodID dataLoaderServiceOnCreateDataLoader;

    jmethodID dataLoaderOnCreate;
    jmethodID dataLoaderOnStart;
    jmethodID dataLoaderOnStop;
    jmethodID dataLoaderOnDestroy;
    jmethodID dataLoaderOnPendingReads;
    jmethodID dataLoaderOnPageReads;
    jmethodID dataLoaderOnFileCreated;

    jclass pendingReadInfo;
    jmethodID pendingReadInfoConstruct;

    jclass readInfo;
    jmethodID readInfoConstruct;

    jclass arrays;
    jmethodID arraysAsList;

    JniIds(JNIEnv* env) {
        auto parcelFileDescriptor = FindClassOrDie(env, "android/os/ParcelFileDescriptor");
        parcelFileDescriptorDup = GetMethodIDOrDie(env, parcelFileDescriptor, "dup",
                                                   "()Landroid/os/ParcelFileDescriptor;");
        parcelFileDescriptorGetFileDescriptor =
                GetMethodIDOrDie(env, parcelFileDescriptor, "getFileDescriptor",
                                 "()Ljava/io/FileDescriptor;");

        incrementalFileSystemConnector = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/incremental/"
                               "IncrementalDataLoaderService$FileSystemConnector"));
        incrementalFileSystemConnectorConstruct =
                GetMethodIDOrDie(env, incrementalFileSystemConnector, "<init>", "(J)V");

        statusListener = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/incremental/"
                               "IncrementalDataLoaderService$StatusListener"));
        statusListenerConstruct = GetMethodIDOrDie(env, statusListener, "<init>", "(J)V");

        dataLoaderParams = (jclass)env->NewGlobalRef(
                FindClassOrDie(env, "android/os/incremental/IncrementalDataLoaderParams"));
        dataLoaderParamsCtor =
                GetMethodIDOrDie(env, dataLoaderParams, "<init>",
                                 "(Landroid/os/incremental/IncrementalDataLoaderParamsParcel;)V");

        auto dataLoaderService =
                FindClassOrDie(env, "android/service/incremental/IncrementalDataLoaderService");
        dataLoaderServiceOnCreateDataLoader =
                GetMethodIDOrDie(env, dataLoaderService, "onCreateDataLoader",
                                 "()Landroid/service/incremental/"
                                 "IncrementalDataLoaderService$DataLoader;");

        auto dataLoader = FindClassOrDie(env,
                                         "android/service/incremental/"
                                         "IncrementalDataLoaderService$DataLoader");
        dataLoaderOnCreate =
                GetMethodIDOrDie(env, dataLoader, "onCreate",
                                 "(Landroid/os/incremental/IncrementalDataLoaderParams;"
                                 "Landroid/service/incremental/"
                                 "IncrementalDataLoaderService$FileSystemConnector;"
                                 "Landroid/service/incremental/"
                                 "IncrementalDataLoaderService$StatusListener;)Z");
        dataLoaderOnStart = GetMethodIDOrDie(env, dataLoader, "onStart", "()Z");
        dataLoaderOnStop = GetMethodIDOrDie(env, dataLoader, "onStop", "()V");
        dataLoaderOnDestroy = GetMethodIDOrDie(env, dataLoader, "onDestroy", "()V");
        dataLoaderOnPendingReads =
                GetMethodIDOrDie(env, dataLoader, "onPendingReads", "(Ljava/util/Collection;)V");
        dataLoaderOnPageReads =
                GetMethodIDOrDie(env, dataLoader, "onPageReads", "(Ljava/util/Collection;)V");
        dataLoaderOnFileCreated = GetMethodIDOrDie(env, dataLoader, "onFileCreated", "(J[B)V");

        pendingReadInfo = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/incremental/"
                               "IncrementalDataLoaderService$FileSystemConnector$PendingReadInfo"));
        pendingReadInfoConstruct = GetMethodIDOrDie(env, pendingReadInfo, "<init>", "(JI)V");

        readInfo = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/incremental/"
                               "IncrementalDataLoaderService$FileSystemConnector$ReadInfo"));
        readInfoConstruct = GetMethodIDOrDie(env, readInfo, "<init>", "(JJII)V");

        arrays = (jclass)env->NewGlobalRef(FindClassOrDie(env, "java/util/Arrays"));
        arraysAsList = GetStaticMethodIDOrDie(env, arrays, "asList",
                                              "([Ljava/lang/Object;)Ljava/util/List;");
    }
};

const JniIds& jniIds(JNIEnv* env) {
    static const JniIds ids(env);
    return ids;
}

} // namespace

ManagedDataLoader::ManagedDataLoader(JavaVM* jvm) : mJvm(jvm) {
    CHECK(mJvm);
}

bool ManagedDataLoader::onCreate(const android::incremental::DataLoaderParams&,
                                 android::incremental::FilesystemConnectorPtr ifs,
                                 android::incremental::StatusListenerPtr listener,
                                 android::incremental::ServiceConnectorPtr service,
                                 android::incremental::ServiceParamsPtr params) {
    CHECK(!mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    jobject ifsc = env->NewObject(jni.incrementalFileSystemConnector,
                                  jni.incrementalFileSystemConnectorConstruct, (jlong)ifs);
    if (!ifsc) {
        LOG(ERROR) << "Failed to obtain Java IncrementalDataLoaderService$FileSystemConnector.";
        return false;
    }

    jobject statusListener =
            env->NewObject(jni.statusListener, jni.statusListenerConstruct, (jlong)listener);
    if (!statusListener) {
        LOG(ERROR) << "Failed to obtain Java StatusListener.";
        return false;
    }

    auto dataLoader = env->CallObjectMethod(service, jni.dataLoaderServiceOnCreateDataLoader);
    if (!dataLoader) {
        LOG(ERROR) << "Failed to create Java DataLoader.";
        return false;
    }

    const auto publicParams =
            env->NewObject(jni.dataLoaderParams, jni.dataLoaderParamsCtor, params);
    if (!publicParams) {
        LOG(ERROR) << "Failed to create Java DataLoaderParams.";
        return false;
    }

    mDataLoader = env->NewGlobalRef(dataLoader);
    return env->CallBooleanMethod(mDataLoader, jni.dataLoaderOnCreate, publicParams, ifsc,
                                  statusListener);
}
bool ManagedDataLoader::onStart() {
    CHECK(mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    return env->CallBooleanMethod(mDataLoader, jni.dataLoaderOnStart);
}
void ManagedDataLoader::onStop() {
    CHECK(mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    return env->CallVoidMethod(mDataLoader, jni.dataLoaderOnStop);
}
void ManagedDataLoader::onDestroy() {
    CHECK(mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    env->CallVoidMethod(mDataLoader, jni.dataLoaderOnDestroy);
    env->DeleteGlobalRef(mDataLoader);
    mDataLoader = nullptr;
}

// IFS callbacks.
void ManagedDataLoader::onPendingReads(const PendingReads& pendingReads) {
    CHECK(mDataLoader);

    auto env = GetOrAttachJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    auto jreads = env->NewObjectArray(pendingReads.size(), jni.pendingReadInfo, nullptr);
    CHECK(jreads);
    for (size_t i = 0, size = pendingReads.size(); i < size; ++i) {
        const auto& read = pendingReads[i];
        auto jread = env->NewObject(jni.pendingReadInfo, jni.pendingReadInfoConstruct,
                                    read.file_ino, read.block_index);
        CHECK(jread);
        env->SetObjectArrayElement(jreads, i, jread);
    }
    auto jlist = env->CallStaticObjectMethod(jni.arrays, jni.arraysAsList, jreads);
    env->CallVoidMethod(mDataLoader, jni.dataLoaderOnPendingReads, jlist);
}

void ManagedDataLoader::onPageReads(const PageReads& pageReads) {
    CHECK(mDataLoader);

    auto env = GetOrAttachJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    auto jreads = env->NewObjectArray(pageReads.size(), jni.readInfo, nullptr);
    CHECK(jreads);
    for (size_t i = 0, size = pageReads.size(); i < size; ++i) {
        const auto& read = pageReads[i];
        auto jread =
                env->NewObject(jni.readInfo, jni.readInfoConstruct, jlong(read.timestamp_us / 1000),
                               jlong(read.file_ino), jint(read.block_index), 1);
        CHECK(jread);
        env->SetObjectArrayElement(jreads, i, jread);
    }
    auto jlist = env->CallStaticObjectMethod(jni.arrays, jni.arraysAsList, jreads);
    env->CallVoidMethod(mDataLoader, jni.dataLoaderOnPageReads, jlist);
}

void ManagedDataLoader::onFileCreated(Inode inode, const RawMetadata& metadata) {
    CHECK(mDataLoader);

    auto env = GetOrAttachJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    auto jMetadataBytes = env->NewByteArray(metadata.size());
    env->SetByteArrayRegion(jMetadataBytes, 0, metadata.size(), (jbyte*)&metadata[0]);
    env->CallVoidMethod(mDataLoader, jni.dataLoaderOnFileCreated, (jlong)inode, jMetadataBytes);
}

} // namespace android::incremental
