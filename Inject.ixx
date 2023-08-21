#define WIN32_LEAN_AND_MEAN
#include <filesystem>
#include <iostream>
#include <Windows.h>

export module Inject;
import text;

struct thread_parameters
{
  [[maybe_unused]] decltype(LoadLibrary)* loadLibrary = LoadLibrary;
  [[maybe_unused]] decltype(GetProcAddress)* getProcAddress = GetProcAddress;
  [[maybe_unused]] TCHAR* dllPath = nullptr;
  explicit thread_parameters(TCHAR* DllPath) { dllPath = DllPath; }
};

struct loader_data
{
  [[maybe_unused]] std::uint8_t* shellCode;
  [[maybe_unused]] thread_parameters* threadParameters;
  [[maybe_unused]] TCHAR* dllPath;
  [[maybe_unused]] std::size_t dllPathSize;
};

/*
        48:83EC 28               | sub rsp, 28                             |
        48:8BD9                  | mov rbx,rcx                             | save to non-volatile register
        48:8D4B 10               | lea rcx,qword ptr ds:[rbx+10]           | offsetof(InjectDLLThreadData, dllPath)
        48:8B09                  | mov rcx,qword ptr ds:[rcx]              | *rcx
        FF13                     | call qword ptr ds:[rbx]                 | offsetof(InjectDLLThreadData, loadLibraryA)
        48:8BC8                  | mov rcx,rax                             |
        BA 01000000              | mov edx,1                               |
        FF53 08                  | call qword ptr ds:[rbx+8]               | offsetof(InjectDLLThreadData, getProcAddress)
        FFD0                     | call rax                                |
        48:83C4 28               | add rsp, 28                             |
        C3                       | ret                                     |
*/
constexpr std::uint8_t ShellCode[] =
    {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8B, 0xD9,
        0x48, 0x8D, 0x4B, 0x10,
        0x48, 0x8B, 0x09,
        0xFF, 0x13,
        0x48, 0x8B, 0xC8,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0xFF, 0x53, 0x08,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
};

void cleanup(HANDLE ProcessHandle, loader_data& Data)
{
    Data.shellCode && VirtualFreeEx(ProcessHandle, Data.shellCode, sizeof(ShellCode), MEM_RELEASE);
    Data.threadParameters && VirtualFreeEx(ProcessHandle, Data.threadParameters, sizeof(thread_parameters), MEM_RELEASE);
    Data.dllPath && VirtualFreeEx(ProcessHandle, Data.dllPath, Data.dllPathSize, MEM_RELEASE);
}

[[nodiscard]] bool initialize(HANDLE ProcessHandle, std::filesystem::path& Path, loader_data& Data)
{
    auto DllString = asa::text::win32Str(Path);
    auto DllSize = (DllString.size() + 1) * (sizeof(decltype(DllString)::traits_type::char_type));

    Data.shellCode = static_cast<std::uint8_t*>(VirtualAllocEx(ProcessHandle, nullptr, sizeof(ShellCode), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    Data.threadParameters = static_cast<thread_parameters*>(VirtualAllocEx(ProcessHandle, nullptr, sizeof(thread_parameters), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE));
    Data.dllPath = static_cast<TCHAR*>(VirtualAllocEx(ProcessHandle, nullptr, DllSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE));
    Data.dllPathSize = DllSize;

    return Data.shellCode && Data.threadParameters && Data.dllPath && Data.dllPathSize;
}

[[nodiscard]] bool writeOne(HANDLE ProcessHandle, void* Where, const void* What, std::size_t Size, const std::string& Tag = "Generic Write")
{
    std::size_t Wrote = 0;
    auto Result = WriteProcessMemory(ProcessHandle, Where, What, Size, &Wrote);
    std::cout << std::format("Wrote {} Bytes For {}\n", Wrote, Tag);
    return Result;
}

[[nodiscard]] bool write(HANDLE ProcessHandle, std::filesystem::path& Path, loader_data& Data, thread_parameters& Parameters)
{
    auto DllString = asa::text::win32Str(Path);
    auto Success = true;
    Success &= writeOne(ProcessHandle, Data.shellCode, ShellCode, sizeof(ShellCode), "Shell Code");
    Success &= Success && writeOne(ProcessHandle, Data.threadParameters, &Parameters, sizeof(thread_parameters), "Thread Parameters");
    Success &= Success && writeOne(ProcessHandle, Data.dllPath, DllString.c_str(), Data.dllPathSize, "Dll Path");
    return Success;
}

[[nodiscard]] bool finalize(HANDLE ProcessHandle, loader_data& Data, bool Result, const std::string& Message = "Completed")
{
    if(ProcessHandle)
        cleanup(ProcessHandle, Data);

    std::cout << std::format("{}\n", Message);
    return Result;
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantFunctionResult"
[[nodiscard]] bool reject(HANDLE ProcessHandle, loader_data& Data, const std::string& Reason = "Unknown Error")
{
    return finalize(ProcessHandle, Data, false,
                    std::format("Loader Failed, Reason: {}", Reason));
}

[[nodiscard]] bool accept(HANDLE ProcessHandle, loader_data& Data, const std::string& Reason = "Success")
{
    return finalize(ProcessHandle, Data, true,
                    std::format("Loader Completed, Reason: {}", Reason));
}
#pragma clang diagnostic pop

export [[nodiscard]] bool inject(DWORD ProcessId, std::filesystem::path& Path)
{
    loader_data LoaderData {};
    auto ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, ProcessId);
    if(!ProcessHandle)
        return reject(ProcessHandle, LoaderData, "Unable to Open Process");

    if(!initialize(ProcessHandle, Path, LoaderData))
        return reject(ProcessHandle, LoaderData, "Unable To Allocate Memory");

    thread_parameters Parameters {LoaderData.dllPath};

    if(!write(ProcessHandle, Path, LoaderData, Parameters))
        return reject(ProcessHandle, LoaderData, "Unable To Write Memory");

    HANDLE Thread = CreateRemoteThread(ProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)(LoaderData.shellCode), LoaderData.threadParameters, 0, nullptr);

    if(!Thread)
        return reject(ProcessHandle, LoaderData, "Thread Creation Failed.");

    auto Result = WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    switch(Result)
    {
      case WAIT_OBJECT_0:
        return accept(ProcessHandle, LoaderData);
      case WAIT_ABANDONED:
        return reject(ProcessHandle, LoaderData, "Thread Abandoned.");
      case WAIT_TIMEOUT:
        return reject(ProcessHandle, LoaderData, "Thread Timeout.");
      default:
        return reject(ProcessHandle, LoaderData, "Unknown Thread Error");
    }
}