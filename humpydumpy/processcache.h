#pragma once
#include <windows.h>
#include <string>
#include <unordered_map>
#include <mutex>

class ProcessCache
{
public:
    static void Initialize(); // call once
    static DWORD GetPid(const std::wstring& processName);
    static void Refresh();    // optional

private:
    static void BuildCache();

    static std::unordered_map<std::wstring, DWORD> s_processMap;
    static std::once_flag s_initFlag;
    static std::mutex s_mutex;
};