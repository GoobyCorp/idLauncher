// Windows includes
#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <tlhelp32.h>

// internal includes
#include "idLauncher.h"
#include "INIReader.h"

// library includes
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

using namespace std;

const char MainModuleName[] = "DOOMEternalx64vk.exe";

void Success() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    cout << "Success!" << endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void Failed() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    cout << "Failed!" << endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

char* ScanIn(const char* pattern, const char* mask, char* begin, unsigned int size)
{
    unsigned int patternLength = strlen(mask);

    for (unsigned int i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (unsigned int j = 0; j < patternLength; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

char* ScanEx(const char* pattern, const char* mask, char* begin, char* end, HANDLE hProc)
{
    char* currentChunk = begin;
    char* match = nullptr;
    SIZE_T bytesRead;

    while (currentChunk < end)
    {
        MEMORY_BASIC_INFORMATION mbi;

        //return nullptr if VirtualQuery fails
        if (!VirtualQueryEx(hProc, currentChunk, &mbi, sizeof(mbi)))
        {
            return nullptr;
        }

        char* buffer = new char[mbi.RegionSize];

        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS)
        {
            DWORD oldprotect;
            if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
            {
                ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
                VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

                char* internalAddress = ScanIn(pattern, mask, buffer, bytesRead);

                if (internalAddress != nullptr)
                {
                    //calculate from internal to external
                    uintptr_t offsetFromBuffer = internalAddress - buffer;
                    match = currentChunk + offsetFromBuffer;
                    delete[] buffer;
                    break;
                }
            }
        }

        currentChunk = currentChunk + mbi.RegionSize;
        delete[] buffer;
    }
    return match;
}

HMODULE GetMainModuleHandle(HANDLE hProcess, const char* modName, LPMODULEINFO mi) {
    // get process modules
    HMODULE hMods[2048];
    DWORD cbNeeded;
    DWORD modCnt = 0;
    while (true) {
        EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
        modCnt = cbNeeded / sizeof(HMODULE);
        if (modCnt > 0)
            break;
        Sleep(10);
    }

    // iterate through each module
    // MODULEINFO mi;
    for (unsigned int i = 0; i < modCnt; i++) {
        char szModName[MAX_PATH];
        if (!GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
            cout << "GetModuleFileNameExA failed!" << endl;

            CloseHandle(hProcess);
            return NULL;
        }

        if (strstr(szModName, modName) == NULL)
            continue;

        // get module information
        if (!GetModuleInformation(hProcess, hMods[i], mi, sizeof(MODULEINFO))) {
            cout << "GetModuleInformation failed!" << endl;

            CloseHandle(hProcess);
            return NULL;
        }

        return hMods[i];
    }

    return NULL;
}

BOOL PatchAddressEx(HANDLE hProcess, const char* pattern, const char* patch, const char* mask, char* start, DWORD size) {
    SIZE_T bw;

    PBYTE pbAddr = (PBYTE)ScanEx(pattern, mask, start, start + size, hProcess);
    if (pbAddr == NULL)
        return FALSE;
    if (!WriteProcessMemory(hProcess, pbAddr, patch, strlen(mask), &bw))
        return FALSE;
    if (bw != strlen(mask))
        return FALSE;
    return TRUE;
}

HANDLE GetProcessByName(const char* procName, LPMODULEINFO mi, PDWORD procId) {
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        cout << "EnumProcesses failed!" << endl;
    }
    DWORD cntProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cntProcesses; i++) {
        DWORD procIdTmp = aProcesses[i];

        if (procIdTmp == 0)
            continue;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procIdTmp);
        if (hProcess == NULL)
            continue;

        HMODULE hMod;
        DWORD cbNeeded;
        char szProcessName[MAX_PATH];
        if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        {
            CloseHandle(hProcess);
            continue;
        }

        if (GetModuleBaseNameA(hProcess, hMod, szProcessName, MAX_PATH) == 0) {
            CloseHandle(hMod);
            CloseHandle(hProcess);
            continue;
        }

        if (strstr(szProcessName, procName) == NULL) {
            CloseHandle(hMod);
            CloseHandle(hProcess);
            continue;
        }

        if (!GetModuleInformation(hProcess, hMod, mi, sizeof(MODULEINFO))) {
            cout << "GetModuleInformation failed!" << endl;

            CloseHandle(hMod);
            CloseHandle(hProcess);
            continue;
        }
        CloseHandle(hMod);

        *procId = procIdTmp;
        return hProcess;
    }
    return NULL;
}

void SetProcessState(DWORD procId, ProcessState ps) {
    // put all threads to sleep or wake them up
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    Thread32First(hThreadSnapshot, &threadEntry);
    do
    {
        if (threadEntry.th32OwnerProcessID == procId) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            if (ps == PROCESS_STATE_SLEEP) {
                SuspendThread(hThread);
            } else if (ps == PROCESS_STATE_WAKE) {
                ResumeThread(hThread);
            }
            CloseHandle(hThread);
        }
    } while (Thread32Next(hThreadSnapshot, &threadEntry));
    CloseHandle(hThreadSnapshot);
}

vector<string> GetFileList(fs::path path)
{
	vector<string> m_file_list;
	fs::directory_iterator end;

	for (fs::directory_iterator i(path); i != end; ++i)
	{
		const fs::path cp = (*i);
		m_file_list.push_back(cp.string());
	}
	return m_file_list;
}

BOOL IsSteam(fs::path path) {
	vector<string> files = GetFileList(path);
	int i = 0;
	for (auto it = files.begin(); it != files.end(); it++, i++) {
		if (strstr((*it).c_str(), "steam_api64.dll") != NULL)
			return TRUE;
	}
	return FALSE;
}

char* GetDoomArgs(int argc, char* argv[]) {
    // argument to start on
    int startArg = 2;

    // calculate argument size
    int argSize = 0;
    for (int i = startArg; i < argc; i++) {
        argSize += strlen(argv[i]);
    }

    // calculate the allocation size for all arguments plus spaces
    int allocSize = (argSize + (argc - startArg)) - 1;
    // allocate a buffer for all the arguments plus the spaces
    char* argComb = (char*)malloc(allocSize);
    // set all bytes to a ' ' character
    memset(argComb, 0x20, allocSize);
    // add null terminator
    argComb[allocSize] = 0;

    // index into the argComb buffer
    int idx = 0;
    for (int i = startArg; i < argc; i++) {
        // copy the arguments into the argComb buffer then skip a character
        memcpy(argComb + idx, argv[i], strlen(argv[i]));
        // argument size plus skip one for the space
        idx += strlen(argv[i]) + 1;
    }

    // return it
    return argComb;
}

int Launch(const char* filename, const char* args = NULL) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    MODULEINFO mi;
    DWORD procId;
    HANDLE hProcess = 0;
    HANDLE hThread = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // create the process
    fs::path p(filename);
    p = fs::absolute(p);

    // check if this is a Steam installation
    BOOL steam = IsSteam(p.parent_path());

    // get the working directory
    string dir = p.parent_path().string();

    // steam://rungameid/782330

    // recreate the arguments
    if (args == NULL) {
        cout << "Startup directory: \"" << dir << "\"" << endl;
        if (!CreateProcessA(NULL, (char*)p.string().c_str(), NULL, NULL, FALSE, 0, NULL, dir.c_str(), &si, &pi)) {
            cout << "CreateProcess failed!" << endl;

            return 1;
        }
    } else {
        string fullPath = p.string();
        fullPath += " ";
        fullPath += args;

        cout << "Startup directory: \"" << dir << "\"" << endl;
        if (!CreateProcessA(NULL, (char*)fullPath.c_str(), NULL, NULL, FALSE, 0, NULL, dir.c_str(), &si, &pi)) {
            cout << "CreateProcess failed!" << endl;

            return 1;
        }
    }

    if (steam) {
        cout << "Steam detected!" << endl;

        WaitForSingleObject(pi.hProcess, INFINITE);
        cout << "Process restarted under Steam..." << endl;

        cout << "Waiting on process to start back under a different process ID..." << endl;
        while (true) {
            hProcess = GetProcessByName(MainModuleName, &mi, &procId);
            if (hProcess != NULL && procId != pi.dwProcessId)
                break;
            // Sleep(40);
        }
        cout << "Found new process with ID " << procId << "!" << endl;
    } else {
        cout << "no-DRM or Bethesda.net detected!" << endl;

        hProcess = pi.hProcess;
        hThread = pi.hThread;
        procId = pi.dwProcessId;

        HMODULE hMainMod = GetMainModuleHandle(hProcess, MainModuleName, &mi);
        if (hMainMod == NULL) {
            cout << "GetMainModuleHandle failed!" << endl;

            TerminateProcess(hProcess, 1);
            return 1;
        }
        CloseHandle(hMainMod);
    }

    // suspend while patching
    cout << "Suspending..." << endl;
    SetProcessState(procId, PROCESS_STATE_SLEEP);

    // parse patches.ini
    INIReader reader("patches.ini");

    DWORD bw;
    if (reader.ParseError() != 0) {
        cout << "Generating default \"patches.ini\"" << endl;

        HANDLE hFile = CreateFileA("patches.ini", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        const char* defaultIni = "[patches]\r\nUnsignedManifest=true\r\nChecksumChecks=true\r\nManifestHashes=true\r\nManifestSizes=true\r\nUnrestrictBinds=true\r\nBlockHTTP=true\r\nresource_loadMostRecent=true";
        WriteFile(hFile, defaultIni, strlen(defaultIni), &bw, NULL);
        CloseHandle(hFile);

        INIReader reader("patches.ini");
    }

    cout << "Reading \"patches.ini\"..." << endl;

    cout << "Patching..." << endl;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // unsigned build-manifest.bin patch
    if (reader.GetBoolean("patches", "UnsignedManifest", true)) {
        cout << "Applying unsigned manifest patch..." << endl;
        if(PatchAddressEx(hProcess, "\x48\x83\xEC\x28\x49\x8B", "\xB8\x01\x00\x00\x00\xC3", "xxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage))
            Success();
        else
            Failed();
    }

    // skip data checksum checks
    /* if (reader.GetBoolean("patches", "ChecksumChecks", true)) {
        cout << "Applying checksum check patch..." << endl;
        if (PatchAddressEx(hProcess, "\x74\x1E\x8B\x53\x48\x41\xB8\xEF\xBE\xAD\xDE", "\xEB\x1E\x8B\x53\x48\x41\xB8\xEF\xBE\xAD\xDE", "xxxxxxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage)) {
            Success();
        } else {
            Failed();
        }
    } */

    // skip checking against hashes inside build-manifest.bin
    if (reader.GetBoolean("patches", "ManifestHashes", true)) {
        cout << "Applying manifest hashes patch..." << endl;
        if(PatchAddressEx(hProcess, "\x74\x20\x48\x8B\x07\x48\x8B\xCF\xFF\x50", "\xEB\x20\x48\x8B\x07\x48\x8B\xCF\xFF\x50", "xxxxxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage))
            Success();
        else
            Failed();
    }

    // skip checking against filesizes inside build-manifest.bin
    if (reader.GetBoolean("patches", "ManifestSizes", true)) {
        cout << "Applying manifest sizes patch..." << endl;
        if (PatchAddressEx(hProcess, "\xFF\x50\x68\x48\x3B\xC5\x74\x43", "\xFF\x50\x68\x48\x89\xC5\xEB\x43", "xxxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage))
            Success();
        else
            Failed();
    }

    // unrestrict binds #1 and #2
    if (reader.GetBoolean("patches", "UnrestrictBinds", true)) {
        cout << "Applying unrestrict binds patches..." << endl;
        BOOL ret0 = PatchAddressEx(hProcess, "\x08\x4C\x8B\x0E\xBA\x01", "\x08\x4C\x8B\x0E\xBA\x00", "xxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage);
        BOOL ret1 = PatchAddressEx(hProcess, "\x08\x4C\x8B\x0F\xBA\x01", "\x08\x4C\x8B\x0F\xBA\x00", "xxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage);
        if (ret0)
            Success();
        else
            Failed();

        if (ret1)
            Success();
        else
            Failed();
    }

    // block HTTP requests
    /* if (reader.GetBoolean("patches", "BlockHTTP", true)) {
        cout << "Applying block HTTP patch..." << endl;
        if(PatchAddressEx(hProcess, "\xE8\x62\xFE\xFF\xFF\x0F\xB6\xC0", "\xB0\x01\x48\x83\xC4\x20\x5B\xC3", "xxxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage)) {
            Success();
        } else {
            Failed();
        }
    } */

    // resource_loadMostRecent
    if (reader.GetBoolean("patches", "resource_loadMostRecent", true)) {
        cout << "Applying resource_loadMostRecent patch..." << endl;
        BOOL ret0 = PatchAddressEx(hProcess, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x40\x53\x48\x83\xEC\x50\x48\x8B\x84\x24\x88\x00\x00\x00\x48\x8B", "\x41\x83\xC9\x10\x53\xEB\x03\x90\xEB\xF6\x48\x83\xEC\x50\x48\x8B\x84\x24\x88\x00\x00\x00\x48\x8B", "xxxxxxxxxxxxxxxxxxxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage);
        BOOL ret1 = PatchAddressEx(hProcess, "\x4C\x8D\x05\x3A\xE8\x37\x02", "\x4C\x8D\x05\x56\xEE\x37\x02", "xxxxxxx", (char*)mi.lpBaseOfDll, mi.SizeOfImage);
        if(ret0)
            Success();
        else
            Failed();

        if(ret1)
            Success();
        else
            Failed();
    }

    // resume after patching
    cout << "Resuming..." << endl;
    SetProcessState(procId, PROCESS_STATE_WAKE);

    cout << "Cleaning up..." << endl;

    // close process handles
	CloseHandle(hThread);
	CloseHandle(hProcess);

    // wait on user input
    cin.get();

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc == 1)  // without executable path and arguments
    {
        fs::path p(argv[0]);
        cout << "Usage: " << p.filename().string() << " <executable path>[arguments]" << endl;
        return 0;
    }
    else if (argc == 2) {  // executable path without arguments
        cout << "Launching without arguments..." << endl;
        return Launch(argv[1]);
    }
    else if (argc >= 3) {  // executable path with arguments
        char* doomArgs = GetDoomArgs(argc, argv);
        cout << "Launching with arguments: \"" << doomArgs << "\"..." << endl;
        return Launch(argv[1], doomArgs);
    }
}