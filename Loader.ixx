#include <filesystem>
#include <Windows.h>
export module Loader;

import text;

export namespace loader
{
  [[nodiscard]] auto findApiDirectory() -> std::filesystem::path
  {
      return std::filesystem::current_path().append(TEXT(R"(ArkApi)"));
  }
  [[nodiscard]] auto findDll() -> std::filesystem::path
  {
      return findApiDirectory().append(TEXT(R"(asa.dll)"));
  }

  [[nodiscard]] auto findExe() -> std::filesystem::path
  {
      return std::filesystem::current_path().append(TEXT(R"(ShooterGameServer.exe)"));
  }

  [[nodiscard]] auto enableBackwardsCompatibility(bool Enabled) -> bool
  {
      if(Enabled)
        return SetDllDirectory(asa::text::win32Str(findApiDirectory()).c_str());
      return true;
  }
}