#include <filesystem>

export module text;

export namespace asa::text
{
    [[nodiscard]] inline auto win32Str(const std::filesystem::path& Path)
    {
#ifdef UNICODE
        return Path.wstring();
#else
        return Path.string();
#endif
    }
}