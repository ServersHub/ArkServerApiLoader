#define WIN32_LEAN_AND_MEAN

#include <filesystem>
#include <thread>
#include <iostream>
#include <Windows.h>

import Inject;
import Loader;
import text;

namespace fs = std::filesystem;

int main() {
    SetConsoleOutputCP(CP_UTF8);

    fs::path server = loader::findExe();
    fs::path dll = loader::findDll();

    loader::enableBackwardsCompatibility(true);

    STARTUPINFOW startupInfo = { 0 };
    PROCESS_INFORMATION	procInfo = { nullptr };
    startupInfo.cb = sizeof(startupInfo);
    DWORD createFlags = CREATE_SUSPENDED;

    CreateProcess(
            server.c_str(),
            nullptr,	// no args
        nullptr,	// default process security
        nullptr,	// default thread security
            FALSE,	// don't inherit handles
            createFlags,
        nullptr,	// no new environment
        nullptr,	// no new cwd
            &startupInfo, &procInfo);

    using namespace std::chrono_literals;

    auto Result = inject(procInfo.dwProcessId, dll);

    ResumeThread(procInfo.hThread);

    WaitForSingleObject(procInfo.hProcess, INFINITE);
    return 0;
}
