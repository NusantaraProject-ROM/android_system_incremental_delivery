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
#define LOG_TAG "incfs-dataloaderconnector"

#include <android-base/logging.h>
#include <nativehelper/JNIHelp.h>
#include <sys/stat.h>
#include <utils/Looper.h>

#include <thread>
#include <unordered_map>

#include "JNIHelpers.h"
#include "ManagedDataLoader.h"
#include "dataloader.h"
#include "incfs.h"

namespace {

using namespace android::dataloader;
using namespace std::literals;
using android::base::unique_fd;

using Inode = android::incfs::Inode;
using RawMetadata = android::incfs::RawMetadata;

struct JniIds {
    struct {
        jint DATA_LOADER_READY;
        jint DATA_LOADER_NOT_READY;
        jint DATA_LOADER_RUNNING;
        jint DATA_LOADER_STOPPED;
        jint DATA_LOADER_SLOW_CONNECTION;
        jint DATA_LOADER_NO_CONNECTION;
        jint DATA_LOADER_CONNECTION_OK;
    } incrementalConstants;

    jmethodID parcelFileDescriptorGetFileDescriptor;

    jfieldID controlCmd;
    jfieldID controlLog;

    jfieldID paramsStaticArgs;
    jfieldID paramsPackageName;
    jfieldID paramsDynamicArgs;

    jfieldID namedFdFd;
    jfieldID namedFdName;

    jclass listener;
    jmethodID listenerOnStatusChanged;

    JniIds(JNIEnv* env) {
        listener = (jclass)env->NewGlobalRef(
                FindClassOrDie(env, "android/content/pm/IDataLoaderStatusListener"));
        listenerOnStatusChanged = GetMethodIDOrDie(env, listener, "onStatusChanged", "(II)V");
        // TODO: use c++ header of IDataLoaderStatusListener directly
        incrementalConstants.DATA_LOADER_READY =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_READY");
        incrementalConstants.DATA_LOADER_NOT_READY =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_NOT_READY");
        incrementalConstants.DATA_LOADER_RUNNING =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_RUNNING");
        incrementalConstants.DATA_LOADER_STOPPED =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_STOPPED");
        incrementalConstants.DATA_LOADER_SLOW_CONNECTION =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_SLOW_CONNECTION");
        incrementalConstants.DATA_LOADER_NO_CONNECTION =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_NO_CONNECTION");
        incrementalConstants.DATA_LOADER_CONNECTION_OK =
                GetStaticIntFieldValueOrDie(env, listener, "DATA_LOADER_CONNECTION_OK");

        CHECK(incrementalConstants.DATA_LOADER_SLOW_CONNECTION ==
              INCREMENTAL_DATA_LOADER_SLOW_CONNECTION);
        CHECK(incrementalConstants.DATA_LOADER_NO_CONNECTION ==
              INCREMENTAL_DATA_LOADER_NO_CONNECTION);
        CHECK(incrementalConstants.DATA_LOADER_CONNECTION_OK ==
              INCREMENTAL_DATA_LOADER_CONNECTION_OK);

        auto parcelFileDescriptor = FindClassOrDie(env, "android/os/ParcelFileDescriptor");
        parcelFileDescriptorGetFileDescriptor =
                GetMethodIDOrDie(env, parcelFileDescriptor, "getFileDescriptor",
                                 "()Ljava/io/FileDescriptor;");

        auto control =
                FindClassOrDie(env, "android/os/incremental/IncrementalFileSystemControlParcel");
        controlCmd = GetFieldIDOrDie(env, control, "cmd", "Landroid/os/ParcelFileDescriptor;");
        controlLog = GetFieldIDOrDie(env, control, "log", "Landroid/os/ParcelFileDescriptor;");

        auto params =
                FindClassOrDie(env, "android/os/incremental/IncrementalDataLoaderParamsParcel");
        paramsStaticArgs = GetFieldIDOrDie(env, params, "staticArgs", "Ljava/lang/String;");
        paramsPackageName = GetFieldIDOrDie(env, params, "packageName", "Ljava/lang/String;");
        paramsDynamicArgs = GetFieldIDOrDie(env, params, "dynamicArgs",
                                            "[Landroid/os/incremental/NamedParcelFileDescriptor;");

        auto namedFd = FindClassOrDie(env, "android/os/incremental/NamedParcelFileDescriptor");
        namedFdName = GetFieldIDOrDie(env, namedFd, "name", "Ljava/lang/String;");
        namedFdFd = GetFieldIDOrDie(env, namedFd, "fd", "Landroid/os/ParcelFileDescriptor;");
    }
};

const JniIds& jniIds(JNIEnv* env) {
    static const JniIds ids(env);
    return ids;
}

bool reportStatusViaCallback(JNIEnv* env, jobject listener, jint storageId, jint status) {
    if (listener == nullptr) {
        ALOGE("No listener object to talk to IncrementalService. "
              "DataLoaderId=%d, "
              "status=%d",
              storageId, status);
        return false;
    }

    const auto& jni = jniIds(env);

    env->CallVoidMethod(listener, jni.listenerOnStatusChanged, storageId, status);
    ALOGI("Reported status back to IncrementalService. DataLoaderId=%d, "
          "status=%d",
          storageId, status);

    return true;
}

class DataLoaderConnector;
using DataLoaderConnectorPtr = std::shared_ptr<DataLoaderConnector>;
using DataLoaderConnectorsMap = std::unordered_map<int, DataLoaderConnectorPtr>;

struct Globals {
    Globals() {
        dataLoaderFactory = new details::DataLoaderFactoryImpl(
                [](auto jvm) { return std::make_unique<ManagedDataLoader>(jvm); });
    }

    DataLoaderFactory managedDataLoaderFactory;
    DataLoaderFactory* dataLoaderFactory;

    std::mutex dataLoaderConnectorsLock;
    // id->DataLoader map
    DataLoaderConnectorsMap dataLoaderConnectors GUARDED_BY(dataLoaderConnectorsLock);

    std::atomic_bool stopped;
    std::thread cmdLooperThread;
    std::thread logLooperThread;
    std::vector<PendingReadInfo> pendingReads;
    std::vector<PageReadInfo> pageReads;
};

static Globals& globals() {
    static Globals globals;
    return globals;
}

struct IncFsLooper : public android::Looper {
    IncFsLooper() : Looper(/*allowNonCallbacks=*/false) {}
    ~IncFsLooper() {}
};

static android::Looper& cmdLooper() {
    static IncFsLooper cmdLooper;
    return cmdLooper;
}

static android::Looper& logLooper() {
    static IncFsLooper logLooper;
    return logLooper;
}

struct DataLoaderParamsPair {
    static DataLoaderParamsPair createFromManaged(JNIEnv* env, jobject params);

    const android::dataloader::DataLoaderParams& dataLoaderParams() const {
        return mDataLoaderParams;
    }
    const ::DataLoaderParams& incrementalDataLoaderParams() const {
        return mIncrementalDataLoaderParams;
    }

private:
    DataLoaderParamsPair(android::dataloader::DataLoaderParams&& dataLoaderParams);

    android::dataloader::DataLoaderParams mDataLoaderParams;
    ::DataLoaderParams mIncrementalDataLoaderParams;
    std::vector<DataLoaderNamedFd> mNamedFds;
};

static constexpr auto kPendingReadsBufferSize = 256;

class DataLoaderConnector : public FilesystemConnector, public StatusListener {
public:
    DataLoaderConnector(JNIEnv* env, jobject service, jint storageId, IncFsControl control,
                        jobject listener)
          : mService(env->NewGlobalRef(service)),
            mCallback(env->NewGlobalRef(listener)),
            mStorageId(storageId),
            mControl(control) {
        env->GetJavaVM(&mJvm);
        CHECK(mJvm != nullptr);
    }
    DataLoaderConnector(const DataLoaderConnector&) = delete;
    DataLoaderConnector(const DataLoaderConnector&&) = delete;
    virtual ~DataLoaderConnector() {
        JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);

        env->DeleteGlobalRef(mService);
        env->DeleteGlobalRef(mCallback);

        close(mControl.cmdFd);
        close(mControl.logFd);
    } // to avoid delete-non-virtual-dtor

    bool onCreate(DataLoaderFactory* factory, const DataLoaderParamsPair& params,
                  jobject managedParams) {
        mDataLoader = factory->onCreate(factory, &params.incrementalDataLoaderParams(), this, this,
                                        mJvm, mService, managedParams);
        if (!mDataLoader) {
            return false;
        }

        JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);
        const auto& jni = jniIds(env);
        reportStatusViaCallback(env, mCallback, mStorageId,
                                jni.incrementalConstants.DATA_LOADER_READY);
        return true;
    }
    bool onStart() {
        CHECK(mDataLoader);
        if (!mDataLoader->onStart(mDataLoader)) {
            JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);
            const auto& jni = jniIds(env);
            reportStatusViaCallback(env, mCallback, mStorageId,
                                    jni.incrementalConstants.DATA_LOADER_NOT_READY);
            return false;
        }
        JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);
        const auto& jni = jniIds(env);
        reportStatusViaCallback(env, mCallback, mStorageId,
                                jni.incrementalConstants.DATA_LOADER_RUNNING);
        return true;
    }
    void onStop() {
        CHECK(mDataLoader);
        return mDataLoader->onStop(mDataLoader);
    }
    void onDestroy() {
        CHECK(mDataLoader);
        return mDataLoader->onDestroy(mDataLoader);
    }
    void onFileCreated(jlong inode, jbyteArray metadataBytes) {
        CHECK(mDataLoader);
        JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);
        auto metadataBytesLength = env->GetArrayLength(metadataBytes);
        RawMetadata rawMetadata(metadataBytesLength);
        env->GetByteArrayRegion(metadataBytes, 0, metadataBytesLength,
                                reinterpret_cast<jbyte*>(&rawMetadata[0]));
        return mDataLoader->onFileCreated(mDataLoader, inode, &rawMetadata[0], metadataBytesLength);
    }
    int onCmdLooperEvent(std::vector<PendingReadInfo>& pendingReads) {
        CHECK(mDataLoader);
        while (true) {
            pendingReads.resize(kPendingReadsBufferSize);
            if (android::incfs::waitForPendingReads(mControl, 0ms, &pendingReads) !=
                        android::incfs::WaitResult::HaveData ||
                pendingReads.empty()) {
                return 1;
            }
            mDataLoader->onPendingReads(mDataLoader, pendingReads.data(), pendingReads.size());
        }
        return 1;
    }
    int onLogLooperEvent(std::vector<PageReadInfo>& pageReads) {
        CHECK(mDataLoader);
        while (true) {
            pageReads.clear();
            if (android::incfs::waitForPageReads(mControl, 0ms, &pageReads) !=
                        android::incfs::WaitResult::HaveData ||
                pageReads.empty()) {
                return 1;
            }
            mDataLoader->onPageReads(mDataLoader, pageReads.data(), pageReads.size());
        }
        return 1;
    }

    int writeBlocks(const incfs_new_data_block blocks[], int blocksCount) const {
        return android::incfs::writeBlocks(mControl, blocks, blocksCount);
    }

    int getRawMetadata(Inode ino, char buffer[], size_t* bufferSize) const {
        return IncFs_GetMetadata(mControl, ino, buffer, bufferSize);
    }

    bool reportStatus(DataLoaderStatus status) {
        if (status < INCREMENTAL_DATA_LOADER_FIRST_STATUS ||
            INCREMENTAL_DATA_LOADER_LAST_STATUS < status) {
            ALOGE("Unable to report invalid status. status=%d", status);
            return false;
        }
        JNIEnv* env = GetOrAttachJNIEnvironment(mJvm);
        return reportStatusViaCallback(env, mCallback, mStorageId, status);
    }

    const IncFsControl& control() const { return mControl; }

private:
    JavaVM* mJvm = nullptr;
    jobject const mService;
    jobject const mCallback;

    ::DataLoader* mDataLoader = nullptr;
    const jint mStorageId;
    const IncFsControl mControl;
};

static int onCmdLooperEvent(int fd, int events, void* data) {
    if (globals().stopped) {
        // No more listeners.
        return 0;
    }
    auto&& dataLoaderConnector = (DataLoaderConnector*)data;
    return dataLoaderConnector->onCmdLooperEvent(globals().pendingReads);
}

static int onLogLooperEvent(int fd, int events, void* data) {
    if (globals().stopped) {
        // No more listeners.
        return 0;
    }
    auto&& dataLoaderConnector = (DataLoaderConnector*)data;
    return dataLoaderConnector->onLogLooperEvent(globals().pageReads);
}

static int createFdFromManaged(JNIEnv* env, jobject pfd) {
    if (!pfd) {
        return -1;
    }

    const auto& jni = jniIds(env);
    auto managedFd = env->CallObjectMethod(pfd, jni.parcelFileDescriptorGetFileDescriptor);
    return dup(jniGetFDFromFileDescriptor(env, managedFd));
}

static IncFsControl createIncFsControlFromManaged(JNIEnv* env, jobject managedControl) {
    const auto& jni = jniIds(env);
    auto cmd = createFdFromManaged(env, env->GetObjectField(managedControl, jni.controlCmd));
    auto log = createFdFromManaged(env, env->GetObjectField(managedControl, jni.controlLog));
    return {cmd, log};
}

DataLoaderParamsPair::DataLoaderParamsPair(android::dataloader::DataLoaderParams&& dataLoaderParams)
      : mDataLoaderParams(std::move(dataLoaderParams)) {
    mIncrementalDataLoaderParams.staticArgs = mDataLoaderParams.staticArgs().c_str();
    mIncrementalDataLoaderParams.packageName = mDataLoaderParams.packageName().c_str();

    mNamedFds.resize(mDataLoaderParams.dynamicArgs().size());
    for (size_t i = 0, size = mNamedFds.size(); i < size; ++i) {
        const auto& arg = mDataLoaderParams.dynamicArgs()[i];
        mNamedFds[i].name = arg.name.c_str();
        mNamedFds[i].fd = arg.fd;
    }
    mIncrementalDataLoaderParams.dynamicArgsSize = mNamedFds.size();
    mIncrementalDataLoaderParams.dynamicArgs = mNamedFds.data();
}

DataLoaderParamsPair DataLoaderParamsPair::createFromManaged(JNIEnv* env, jobject managedParams) {
    const auto& jni = jniIds(env);

    std::string staticArgs(
            env->GetStringUTFChars((jstring)env->GetObjectField(managedParams,
                                                                jni.paramsStaticArgs),
                                   nullptr));
    std::string packageName(
            env->GetStringUTFChars((jstring)env->GetObjectField(managedParams,
                                                                jni.paramsPackageName),
                                   nullptr));

    auto dynamicArgsArray = (jobjectArray)env->GetObjectField(managedParams, jni.paramsDynamicArgs);

    size_t size = env->GetArrayLength(dynamicArgsArray);
    std::vector<android::dataloader::DataLoaderParams::NamedFd> dynamicArgs(size);
    for (size_t i = 0; i < size; ++i) {
        auto dynamicArg = env->GetObjectArrayElement(dynamicArgsArray, i);
        auto pfd = env->GetObjectField(dynamicArg, jni.namedFdFd);
        auto fd = env->CallObjectMethod(pfd, jni.parcelFileDescriptorGetFileDescriptor);
        dynamicArgs[i].fd = jniGetFDFromFileDescriptor(env, fd);
        dynamicArgs[i].name =
                (env->GetStringUTFChars((jstring)env->GetObjectField(dynamicArg, jni.namedFdName),
                                        nullptr));
    }

    return DataLoaderParamsPair(android::dataloader::DataLoaderParams(std::move(staticArgs),
                                                                      std::move(packageName),
                                                                      std::move(dynamicArgs)));
}

static void cmdLooperThread() {
    constexpr auto kTimeoutMsecs = 60 * 1000;
    while (!globals().stopped) {
        cmdLooper().pollAll(kTimeoutMsecs);
    }
}

static void logLooperThread() {
    constexpr auto kTimeoutMsecs = 60 * 1000;
    while (!globals().stopped) {
        logLooper().pollAll(kTimeoutMsecs);
    }
}

static std::string pathFromFd(int fd) {
    static constexpr char fdNameFormat[] = "/proc/self/fd/%d";
    char fdNameBuffer[NELEM(fdNameFormat) + 11 + 1]; // max int length + '\0'
    snprintf(fdNameBuffer, NELEM(fdNameBuffer), fdNameFormat, fd);

    std::string res;
    // lstat() is supposed to return us exactly the needed buffer size, but
    // somehow it may also return a smaller (but still >0) st_size field.
    // That's why let's only use it for the initial estimate.
    struct stat st = {};
    if (::lstat(fdNameBuffer, &st) || st.st_size == 0) {
        st.st_size = PATH_MAX;
    }
    auto bufSize = st.st_size;
    for (;;) {
        res.resize(bufSize + 1, '\0');
        auto size = ::readlink(fdNameBuffer, &res[0], res.size());
        if (size < 0) {
            return {};
        }
        if (size > bufSize) {
            // File got renamed in between lstat() and readlink() calls? Retry.
            bufSize *= 2;
            continue;
        }
        res.resize(size);
        return res;
    }
}

} // namespace

void DataLoader_Initialize(struct ::DataLoaderFactory* factory) {
    CHECK(factory) << "DataLoader factory is invalid.";
    globals().dataLoaderFactory = factory;
}

int DataLoader_FilesystemConnector_writeBlocks(DataLoaderFilesystemConnectorPtr ifs,
                                               const struct incfs_new_data_block blocks[],
                                               int blocksCount) {
    auto connector = static_cast<DataLoaderConnector*>(ifs);
    return connector->writeBlocks(blocks, blocksCount);
}

int DataLoader_FilesystemConnector_getRawMetadata(DataLoaderFilesystemConnectorPtr ifs,
                                                  IncFsInode ino, char buffer[],
                                                  size_t* bufferSize) {
    auto connector = static_cast<DataLoaderConnector*>(ifs);
    return connector->getRawMetadata(ino, buffer, bufferSize);
}

int DataLoader_StatusListener_reportStatus(DataLoaderStatusListenerPtr listener,
                                           DataLoaderStatus status) {
    auto connector = static_cast<DataLoaderConnector*>(listener);
    return connector->reportStatus(status);
}

bool DataLoaderService_OnCreate(JNIEnv* env, jobject service, jint storageId, jobject control,
                                jobject params, jobject listener) {
    auto reportNotReady = [listener, storageId](JNIEnv* env) {
        const auto& jni = jniIds(env);
        reportStatusViaCallback(env, listener, storageId,
                                jni.incrementalConstants.DATA_LOADER_NOT_READY);
    };
    std::unique_ptr<JNIEnv, decltype(reportNotReady)> reportNotReadyOnExit(env, reportNotReady);

    auto nativeControl = createIncFsControlFromManaged(env, control);
    ALOGE("DataLoader::create1 cmd: %d/%s", nativeControl.cmdFd,
          pathFromFd(nativeControl.cmdFd).c_str());
    ALOGE("DataLoader::create1 log: %d/%s", nativeControl.logFd,
          pathFromFd(nativeControl.logFd).c_str());

    auto nativeParams = DataLoaderParamsPair::createFromManaged(env, params);
    ALOGE("DataLoader::create2: %s/%s/%d", nativeParams.dataLoaderParams().staticArgs().c_str(),
          nativeParams.dataLoaderParams().packageName().c_str(),
          (int)nativeParams.dataLoaderParams().dynamicArgs().size());

    CHECK(globals().dataLoaderFactory) << "Unable to create DataLoader: factory is missing.";
    auto dataLoaderConnector =
            std::make_unique<DataLoaderConnector>(env, service, storageId, nativeControl, listener);
    {
        std::lock_guard lock{globals().dataLoaderConnectorsLock};
        auto [dlIt, dlInserted] =
                globals().dataLoaderConnectors.try_emplace(storageId,
                                                           std::move(dataLoaderConnector));
        if (!dlInserted) {
            ALOGE("Failed to insert id(%d)->DataLoader mapping, fd already "
                  "exists",
                  storageId);
            return false;
        }
        if (!dlIt->second->onCreate(globals().dataLoaderFactory, nativeParams, params)) {
            globals().dataLoaderConnectors.erase(dlIt);
            return false;
        }
    }

    reportNotReadyOnExit.release();
    return true;
}

bool DataLoaderService_OnStart(jint storageId) {
    IncFsControl control;
    DataLoaderConnectorPtr dataLoaderConnector;
    {
        std::lock_guard lock{globals().dataLoaderConnectorsLock};
        auto dlIt = globals().dataLoaderConnectors.find(storageId);
        if (dlIt == globals().dataLoaderConnectors.end()) {
            ALOGE("Failed to start id(%d): not found", storageId);
            return false;
        }
        dataLoaderConnector = dlIt->second;
        if (!dataLoaderConnector->onStart()) {
            ALOGE("Failed to start id(%d): onStart returned false", storageId);
            return false;
        }

        control = dataLoaderConnector->control();

        // Create loopers while we are under lock.
        if (control.cmdFd >= 0 && !globals().cmdLooperThread.joinable()) {
            cmdLooper();
            globals().cmdLooperThread = std::thread(&cmdLooperThread);
        }
        if (control.logFd >= 0 && !globals().logLooperThread.joinable()) {
            logLooper();
            globals().logLooperThread = std::thread(&logLooperThread);
        }
    }

    if (control.cmdFd >= 0) {
        cmdLooper().addFd(control.cmdFd, android::Looper::POLL_CALLBACK,
                          android::Looper::EVENT_INPUT, &onCmdLooperEvent,
                          dataLoaderConnector.get());
        cmdLooper().wake();
    }

    if (control.logFd >= 0) {
        logLooper().addFd(control.logFd, android::Looper::POLL_CALLBACK,
                          android::Looper::EVENT_INPUT, &onLogLooperEvent,
                          dataLoaderConnector.get());
        logLooper().wake();
    }

    return true;
}

bool DataLoaderService_OnStop(jint storageId) {
    IncFsControl control;
    {
        std::lock_guard lock{globals().dataLoaderConnectorsLock};
        auto dlIt = globals().dataLoaderConnectors.find(storageId);
        if (dlIt == globals().dataLoaderConnectors.end()) {
            ALOGE("Failed to stop id(%d): not found", storageId);
            return false;
        }
        control = dlIt->second->control();
    }

    if (control.cmdFd >= 0) {
        cmdLooper().removeFd(control.cmdFd);
        cmdLooper().wake();
    }
    if (control.logFd >= 0) {
        logLooper().removeFd(control.logFd);
        logLooper().wake();
    }

    {
        std::lock_guard lock{globals().dataLoaderConnectorsLock};
        auto dlIt = globals().dataLoaderConnectors.find(storageId);
        if (dlIt == globals().dataLoaderConnectors.end()) {
            ALOGE("Failed to stop id(%d): not found", storageId);
            return false;
        }
        auto&& dataLoaderConnector = dlIt->second;
        if (dataLoaderConnector) {
            dataLoaderConnector->onStop();
        }
    }

    return true;
}

bool DataLoaderService_OnDestroy(jint storageId) {
    DataLoaderService_OnStop(storageId);

    std::lock_guard lock{globals().dataLoaderConnectorsLock};
    auto dlIt = globals().dataLoaderConnectors.find(storageId);
    if (dlIt == globals().dataLoaderConnectors.end()) {
        ALOGE("Failed to remove id(%d): not found", storageId);
        return false;
    }
    auto&& dataLoaderConnector = dlIt->second;
    dataLoaderConnector->onDestroy();
    globals().dataLoaderConnectors.erase(dlIt);
    return true;
}

bool DataLoaderService_OnFileCreated(jint storageId, jlong inode, jbyteArray metadata) {
    std::lock_guard lock{globals().dataLoaderConnectorsLock};
    auto dlIt = globals().dataLoaderConnectors.find(storageId);
    if (dlIt == globals().dataLoaderConnectors.end()) {
        ALOGE("Failed to handle onFileCreated for id(%d): not found", storageId);
        return false;
    }
    auto&& dataLoaderConnector = dlIt->second;
    if (dataLoaderConnector) {
        dataLoaderConnector->onFileCreated(inode, metadata);
    }
    return true;
}
