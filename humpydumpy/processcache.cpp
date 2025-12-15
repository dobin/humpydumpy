#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>

#include "processcache.h"

std::unordered_map<std::wstring, DWORD> ProcessCache::s_processMap;
std::once_flag ProcessCache::s_initFlag;
std::mutex ProcessCache::s_mutex;

static std::wstring ToLower(const std::wstring& s)
{
    std::wstring result = s;
    std::transform(result.begin(), result.end(), result.begin(), towlower);
    return result;
}

void ProcessCache::Initialize()
{
    std::call_once(s_initFlag, BuildCache);
}

void ProcessCache::BuildCache()
{
    std::lock_guard<std::mutex> lock(s_mutex);
    s_processMap.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            std::wstring name = ToLower(pe.szExeFile);
            s_processMap.emplace(name, pe.th32ProcessID);
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
}

DWORD ProcessCache::GetPid(const std::wstring& processName)
{
    Initialize();

    std::lock_guard<std::mutex> lock(s_mutex);

    auto it = s_processMap.find(ToLower(processName));
    if (it != s_processMap.end())
        return it->second;

    return 0;
}

void ProcessCache::Refresh()
{
    BuildCache();
}
