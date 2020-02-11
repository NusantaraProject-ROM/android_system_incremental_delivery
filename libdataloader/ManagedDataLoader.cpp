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
#define LOG_TAG "dataloader-manageddataloader"

#include "ManagedDataLoader.h"

#include <android-base/logging.h>

#include "JNIHelpers.h"

namespace android::dataloader {

namespace {

struct JniIds {
    jclass dataLoaderParams;
    jmethodID dataLoaderParamsConstruct;

    jclass fileSystemConnector;
    jmethodID fileSystemConnectorConstruct;

    jmethodID dataLoaderServiceOnCreateDataLoader;

    jmethodID dataLoaderOnCreate;
    jmethodID dataLoaderOnPrepareImage;

    JniIds(JNIEnv* env) {
        dataLoaderParams = (jclass)env->NewGlobalRef(
                FindClassOrDie(env, "android/content/pm/DataLoaderParams"));
        dataLoaderParamsConstruct =
                GetMethodIDOrDie(env, dataLoaderParams, "<init>",
                                 "(Landroid/content/pm/DataLoaderParamsParcel;)V");

        fileSystemConnector = (jclass)env->NewGlobalRef(
                FindClassOrDie(env,
                               "android/service/dataloader/DataLoaderService$FileSystemConnector"));
        fileSystemConnectorConstruct = GetMethodIDOrDie(env, fileSystemConnector, "<init>", "(J)V");

        auto dataLoaderService =
                FindClassOrDie(env, "android/service/dataloader/DataLoaderService");
        dataLoaderServiceOnCreateDataLoader =
                GetMethodIDOrDie(env, dataLoaderService, "onCreateDataLoader",
                                 "(Landroid/content/pm/DataLoaderParams;)Landroid/service/"
                                 "dataloader/DataLoaderService$DataLoader;");

        auto dataLoader =
                FindClassOrDie(env, "android/service/dataloader/DataLoaderService$DataLoader");
        dataLoaderOnCreate =
                GetMethodIDOrDie(env, dataLoader, "onCreate",
                                 "(Landroid/content/pm/DataLoaderParams;Landroid/service/"
                                 "dataloader/DataLoaderService$FileSystemConnector;)Z");
        dataLoaderOnPrepareImage =
                GetMethodIDOrDie(env, dataLoader, "onPrepareImage",
                                 "(Ljava/util/Collection;Ljava/util/Collection;)Z");
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

bool ManagedDataLoader::onCreate(const android::dataloader::DataLoaderParams&,
                                 android::dataloader::FilesystemConnectorPtr ifs,
                                 android::dataloader::StatusListenerPtr listener,
                                 android::dataloader::ServiceConnectorPtr service,
                                 android::dataloader::ServiceParamsPtr params) {
    CHECK(!mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    jobject dlp = env->NewObject(jni.dataLoaderParams, jni.dataLoaderParamsConstruct, params);
    jobject ifsc =
            env->NewObject(jni.fileSystemConnector, jni.fileSystemConnectorConstruct, (jlong)ifs);

    auto dataLoader = env->CallObjectMethod(service, jni.dataLoaderServiceOnCreateDataLoader, dlp);
    if (!dataLoader) {
        LOG(ERROR) << "Failed to create Java DataLoader.";
        return false;
    }
    if (env->ExceptionCheck()) {
        return false;
    }

    mDataLoader = env->NewGlobalRef(dataLoader);
    return env->CallBooleanMethod(mDataLoader, jni.dataLoaderOnCreate, dlp, ifsc);
}

void ManagedDataLoader::onDestroy() {
    CHECK(mDataLoader);

    JNIEnv* env = GetJNIEnvironment(mJvm);

    env->DeleteGlobalRef(mDataLoader);
    mDataLoader = nullptr;
}

// FS callbacks.
bool ManagedDataLoader::onPrepareImage(jobject addedFiles, jobject removedFiles) {
    CHECK(mDataLoader);

    auto env = GetOrAttachJNIEnvironment(mJvm);
    const auto& jni = jniIds(env);

    return env->CallBooleanMethod(mDataLoader, jni.dataLoaderOnPrepareImage, addedFiles,
                                  removedFiles);
}

} // namespace android::dataloader
