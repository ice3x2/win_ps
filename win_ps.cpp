// win_ps.cpp - GNU-style ps command for Windows
// 구현: 기본 PID/TIME/NAME/CMD 출력, -f/-l 옵션, 정렬/필터/출력 포맷 지원

#define UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <io.h>
#include <fcntl.h>
#include <psapi.h>
#include <sddl.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm>
#include <winternl.h>
#include <thread>
#pragma comment(lib, "ntdll.lib")

const std::wstring VERSION = L"1.0.0";

typedef NTSTATUS(WINAPI* PFN_NtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
PFN_NtQueryInformationProcess pNtQueryInformationProcess = nullptr;

// 프로세스 정보 구조체
struct ProcInfo {
    std::wstring user;
    DWORD pid;
    DWORD ppid;
    std::wstring exeName;
	// 모든 인자가 포함된 명령어
    std::wstring cmd;
    std::wstring name;
    std::wstring time;
    double cpuPercent = 0;
    DWORD priority = 0;
    std::wstring startTime;

    // CPU 사용률 계산을 위한 필드 추가
    ULONGLONG lastKernelTime = 0;
    ULONGLONG lastUserTime = 0;
    ULONGLONG lastUpdateTime = 0;

};

// 도움말 출력
void PrintHelp(const std::wstring& exeName) {
    std::wcout <<
        L"Usage: " << exeName << L" [options]\n\n"
        L"Standard options (GNU ps compatible):\n"
        L"  -A, -e                 Show all processes\n"
        L"  -f                     Full-format listing (adds PPID, STIME, full CMD)\n"
        L"  -l                     Long format (adds PPID, C, PRI)\n"
        L"  -u USER                Filter by user name\n"
        L"  -p PID                 Filter by PID\n"
        L"  -C NAME                Filter by executable name\n"
        L"  -o FIELDS              Select output columns (comma-separated)\n"
        L"  --sort FIELDS          Sort by fields, support multiple and reverse with - prefix\n"
        L"  -h, --help             Show this help message\n"
        L"\nAvailable fields: pid, ppid, user, name, time, cmd, pri, c, stime\n";
}

// 함수 선언
std::wstring GetCommandLine(HANDLE hProcess);
std::wstring GetUserFromProcess(HANDLE hProcess);
std::wstring FormatProcessTime(FILETIME kernelTime, FILETIME userTime);
bool PrintVersionIfNeeded(int argc, wchar_t* argv[]);

bool ParseArguments(int argc, wchar_t* argv[],
    std::map<std::wstring, std::wstring>& args,
    std::vector<std::wstring>& output_fields,
    bool& showHelp, std::wstring& exeName);

std::vector<ProcInfo> CollectProcesses(const std::map<std::wstring, std::wstring>& args, std::vector<std::wstring>& output_fields);

void PrintHeader(const std::vector<std::wstring>& fields);
void PrintProcesses(const std::vector<ProcInfo>& procs, const std::vector<std::wstring>& fields);

std::vector<std::wstring> _output_fields;

// main 함수  
int wmain(int argc, wchar_t* argv[]) {  

    _setmode(_fileno(stdout), _O_U16TEXT);

    
	


	// GetProcAddress를 사용하여 NtQueryInformationProcess 함수 포인터 가져오기

   pNtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(  
       GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");  

   std::map<std::wstring, std::wstring> args;  
   
   std::wstring exeName;  
   bool showHelp = false;  
   bool opt_f = false, opt_l = false;  
   if (PrintVersionIfNeeded(argc, argv)) return 0;
   if (!ParseArguments(argc, argv, args, _output_fields, showHelp, exeName)) return 1;
   opt_f = args.count(L"f") > 0;  
   opt_l = args.count(L"l") > 0;  

   if (showHelp) {  
       PrintHelp(exeName);  
       return 0;  
   }  

   if (_output_fields.empty()) {
       _output_fields = { L"pid", L"time" };

       if (opt_f || opt_l) _output_fields.push_back(L"ppid");
       if (opt_f) _output_fields.push_back(L"stime");
       if (opt_l) {  
           _output_fields.push_back(L"c");
           _output_fields.push_back(L"pri");
       }  

       // 마지막에 name과 cmd를 추가  
       _output_fields.push_back(L"name");
       if (opt_f) {
           _output_fields.push_back(L"cmd");
       }
   }  

   auto result = CollectProcesses(args, _output_fields);  
   PrintHeader(_output_fields);
   PrintProcesses(result, _output_fields);  
   return 0;  
}


bool PrintVersionIfNeeded(int argc, wchar_t* argv[]) {
	for (int i = 1; i < argc; ++i) {
		if (wcscmp(argv[i], L"--version") == 0 || wcscmp(argv[i], L"-v") == 0) {
			std::wcout << L"Version: " << VERSION << std::endl;
			return true;
		}
	}
	return false;
	
}



// 인자 파싱 함수
bool ParseArguments(int argc, wchar_t* argv[], std::map<std::wstring, std::wstring>& args, std::vector<std::wstring>& output_fields, bool& showHelp, std::wstring& exeName) 
{
    // 실행 파일 이름 설정
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    exeName = exePath;
    size_t slash = exeName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) exeName = exeName.substr(slash + 1);
    size_t dot = exeName.find_last_of(L'.');
    if (dot != std::wstring::npos) exeName = exeName.substr(0, dot);

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        // 도움말 출력
        if (arg == L"-h" || arg == L"--help") {
            showHelp = true;
            return true;
        }

        bool isValueOption = (arg == L"-u" || arg == L"-p" || arg == L"-C" || arg == L"-o" || arg == L"--sort") && i + 1 < argc;

        // 단일 문자 옵션 묶음 처리 (-fl 등)
        if (arg.size() > 1 && arg[0] == L'-' && arg[1] != L'-') {
            for (size_t j = 1; j < arg.size(); ++j) {
                wchar_t ch = arg[j];
                if (ch == L'f') args[L"f"] = L"1";
                else if (ch == L'l') args[L"l"] = L"1";
                else if (ch == L'e' || ch == L'A') {
                    // -e, -A 무시 (기본값이 전체 목록 출력)
                }
                else if(!isValueOption){
                    std::wcerr << L"Unknown option: -" << ch << std::endl;
                }
            }
        }

        // 키-값 인자
        if (isValueOption) {
            // 값 옵션임을 출력.
		    std::wstring val = argv[++i];
            if (arg == L"-u") args[L"user"] = val;
            else if (arg == L"-p") args[L"pid"] = val;
            else if (arg == L"-C") args[L"name"] = val;
            else if (arg == L"-o") {
                args[L"output"] = val;  
                size_t start = 0, end;  
                while ((end = val.find(L',', start)) != std::wstring::npos) {  
                    output_fields.push_back(val.substr(start, end - start));  
                    start = end + 1;  
                }  
                output_fields.push_back(val.substr(start));  
                
            }
            else if (arg == L"--sort") args[L"sort"] = val;

        }
    }

    return true;

}

/*DWORD GetPhysicalCoreCount() {
    DWORD physicalCoreCount = 0;

    // GetLogicalProcessorInformationEx를 사용하여 물리적 코어 수 계산
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buffer = nullptr;
    DWORD bufferSize = 0;

    // 버퍼 크기 확인
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)malloc(bufferSize);
        if (!buffer) return 0;

        if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &bufferSize)) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX current = buffer;
            DWORD offset = 0;

            // RelationProcessorCore를 기준으로 물리적 코어 수 계산
            while (offset < bufferSize) {
                if (current->Relationship == RelationProcessorCore) {
                    physicalCoreCount++;
                }
                offset += current->Size;
                current = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)((BYTE*)buffer + offset);
            }
        }
        free(buffer);
    }

    return physicalCoreCount;
}*/

// CPU 사용률 계산을 위한 정보 수집 함수
void UpdateProcessCpuUsage(std::map<DWORD, ProcInfo>& procMap) {
    static bool firstRun = true;

    // 현재 시스템 시간 가져오기
    FILETIME sysIdleTime, sysKernelTime, sysUserTime, sysCurrentTime;
    GetSystemTimes(&sysIdleTime, &sysKernelTime, &sysUserTime);
    GetSystemTimeAsFileTime(&sysCurrentTime);

    ULONGLONG currentTime = ((ULONGLONG)sysCurrentTime.dwHighDateTime << 32) | sysCurrentTime.dwLowDateTime;
     

    // 첫 실행이면 초기값만 저장하고 리턴
    if (firstRun) {
        firstRun = false;
        for (auto& [pid, procInfo] : procMap) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProc) continue;

            FILETIME createTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
                procInfo.lastKernelTime = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
                procInfo.lastUserTime = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
                procInfo.lastUpdateTime = currentTime;
            }
            CloseHandle(hProc);
        }
        // 초기값만 설정하고 1초 대기 후 다시 측정
        Sleep(1000);
        return;
    }

    // 논리 코어 수
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCores = sysInfo.dwNumberOfProcessors;
	// 물리적 코어 수
    //DWORD numCores = GetPhysicalCoreCount();

    // 각 프로세스의 CPU 사용률 계산
    for (auto& [pid, procInfo] : procMap) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) continue;

        FILETIME createTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
            ULONGLONG newKernelTime = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
            ULONGLONG newUserTime = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;

            // 이전 측정값이 있으면 차이를 계산
            if (procInfo.lastUpdateTime > 0) {
                ULONGLONG kernelDiff = newKernelTime - procInfo.lastKernelTime;
                ULONGLONG userDiff = newUserTime - procInfo.lastUserTime;
                ULONGLONG totalDiff = kernelDiff + userDiff;

                ULONGLONG timeDiff = currentTime - procInfo.lastUpdateTime;

                if (timeDiff > 0) {
                   
                    procInfo.cpuPercent = ((double)totalDiff / timeDiff) * 100.0 / numCores;
                }
            }

            // 현재 값을 저장
            procInfo.lastKernelTime = newKernelTime;
            procInfo.lastUserTime = newUserTime;
            procInfo.lastUpdateTime = currentTime;

            // 누적 CPU 시간 문자열 (MM:SS) 업데이트
            procInfo.time = FormatProcessTime(kernelTime, userTime);

            // STIME (시작 시각 HH:MM) 업데이트
            SYSTEMTIME sysTime, localTime;
            if (FileTimeToSystemTime(&createTime, &sysTime) &&
                SystemTimeToTzSpecificLocalTime(nullptr, &sysTime, &localTime)) {
                wchar_t stimeBuf[32];
                swprintf(stimeBuf, 32, L"%02d:%02d", localTime.wHour, localTime.wMinute);
                procInfo.startTime = stimeBuf;
            }
        }

        CloseHandle(hProc);
    }
}



// 커맨드 라인 추출 함수
std::wstring GetCommandLine(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    if (pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len)) return L"";

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) return L"";

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), nullptr)) return L"";

    std::vector<wchar_t> buffer(params.CommandLine.Length / sizeof(wchar_t) + 1);
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, buffer.data(), params.CommandLine.Length, nullptr)) {
        return L"";
    }
    return std::wstring(buffer.data(), params.CommandLine.Length / sizeof(wchar_t));
}

// 프로세스 실행 사용자명 추출
std::wstring GetUserFromProcess(HANDLE hProcess) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return L"";

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buffer(len);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) {
        CloseHandle(hToken);
        return L"";
    }

    SID* sid = (SID*)((TOKEN_USER*)buffer.data())->User.Sid;
    wchar_t name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(nullptr, sid, name, &nameLen, domain, &domainLen, &use)) {
        CloseHandle(hToken);
        return name;
    }
    CloseHandle(hToken);
    return L"";
}

// CPU 시간 형식화 (kernel + user time)
std::wstring FormatProcessTime(FILETIME kernelTime, FILETIME userTime) {
    ULONGLONG k = ((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONGLONG u = ((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;
    ULONGLONG totalSec = (k + u) / 10000000ULL; // 100-ns 단위 → 초
    wchar_t buf[32];
    swprintf(buf, 32, L"%02llu:%02llu", totalSec / 60, totalSec % 60);
    return buf;
}


// 정렬 적용 함수
void ApplySorting(std::vector<ProcInfo>& procs, const std::wstring& sortExpr) {
    std::vector<std::pair<std::wstring, bool>> keys;
    size_t start = 0, end;
    while ((end = sortExpr.find(L',', start)) != std::wstring::npos) {
        std::wstring key = sortExpr.substr(start, end - start);
        bool desc = !key.empty() && key[0] == L'-';
        if (desc) key = key.substr(1);
        keys.emplace_back(key, desc);
        start = end + 1;
    }
    std::wstring key = sortExpr.substr(start);
    bool desc = !key.empty() && key[0] == L'-';
    if (desc) key = key.substr(1);
    if (!key.empty()) keys.emplace_back(key, desc);

    std::sort(procs.begin(), procs.end(), [&](const ProcInfo& a, const ProcInfo& b) {
        for (auto& [field, desc] : keys) {
            int cmp = 0;
            if (field == L"pid") cmp = (int)a.pid - (int)b.pid;
            else if (field == L"ppid") cmp = (int)a.ppid - (int)b.ppid;
            else if (field == L"user") cmp = a.user.compare(b.user);
            else if (field == L"name") cmp = a.name.compare(b.name);
            else if (field == L"time") cmp = a.time.compare(b.time);
            else if (field == L"pri") cmp = (int)a.priority - (int)b.priority;
			else if (field == L"c") cmp = (int)a.cpuPercent - (int)b.cpuPercent;
			else if (field == L"stime") cmp = a.startTime.compare(b.startTime);
			else if (field == L"cmd") cmp = a.cmd.compare(b.cmd);
			else continue; // 알 수 없는 필드는 무시
            if (cmp != 0) return desc ? cmp > 0 : cmp < 0;
        }
        return false;
    });

	



}


// 프로세스 수집 함수  
std::vector<ProcInfo> CollectProcesses(const std::map<std::wstring, std::wstring>& args,std::vector<std::wstring>& output_fields) {
   // 프로세스 맵 (PID를 키로 사용)
   std::map<DWORD, ProcInfo> procMap;

   std::vector<ProcInfo> result;  
   HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  
   if (hSnap == INVALID_HANDLE_VALUE) return result;  

   bool filter_user = args.count(L"user");  
   bool filter_pid = args.count(L"pid");  
   bool filter_name = args.count(L"name");  

   PROCESSENTRY32W pe;  
   pe.dwSize = sizeof(pe);  

   if (Process32FirstW(hSnap, &pe)) {  
       do {  
           HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);  
           if (!hProc) continue;  

           ProcInfo info;  
           info.pid = pe.th32ProcessID;  
           info.ppid = pe.th32ParentProcessID;  
           info.name = pe.szExeFile;  

		   // output_fields 에 "cmd" 가 포함되어 있으면 cmd를 가져옴
		   if (std::find(output_fields.begin(), output_fields.end(), L"cmd") != output_fields.end()) {
               info.cmd = GetCommandLine(hProc);
		   }



           info.user = GetUserFromProcess(hProc);  
           if (info.user.empty()) info.user = L"?";  


		   // startTime, time, priority 정보 가져오기
           if (std::find(output_fields.begin(), output_fields.end(), L"stime") != output_fields.end() ||
               std::find(output_fields.begin(), output_fields.end(), L"time") != output_fields.end() ||
               std::find(output_fields.begin(), output_fields.end(), L"pri") != output_fields.end() || 
               std::find(output_fields.begin(), output_fields.end(), L"c") != output_fields.end()) {


               FILETIME createTime, exitTime, kernelTime, userTime;
               if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
                   // 누적 CPU 시간 문자열 (MM:SS)
                   info.time = FormatProcessTime(kernelTime, userTime);

                   // STIME (시작 시각 HH:MM)
                   SYSTEMTIME sysTime, localTime;
                   if (FileTimeToSystemTime(&createTime, &sysTime) &&
                       SystemTimeToTzSpecificLocalTime(nullptr, &sysTime, &localTime)) {
                       wchar_t stimeBuf[32];
                       swprintf(stimeBuf, 32, L"%02d:%02d", localTime.wHour, localTime.wMinute);
                       info.startTime = stimeBuf;
                   }

               }
               info.priority = GetPriorityClass(hProc);

               CloseHandle(hProc);
           }

           

           if (filter_user && args.at(L"user") != info.user) continue;  
           if (filter_pid && std::to_wstring(info.pid) != args.at(L"pid")) continue;  
           if (filter_name && _wcsicmp(info.name.c_str(), args.at(L"name").c_str()) != 0) continue;  

           result.push_back(info);  

           procMap[info.pid] = info;

       } while (Process32NextW(hSnap, &pe));  
   }  

   CloseHandle(hSnap);  

   
   // outout_fileds 에 "c" 가 포함되어 있으면 CPU 사용률을 계산
   if (std::find(output_fields.begin(), output_fields.end(), L"c") != output_fields.end() || 
       std::find(output_fields.begin(), output_fields.end(), L"C") != output_fields.end()) {
       
	   // CPU 사용률 정보 초기화 (첫 번째 스냅샷)
	   UpdateProcessCpuUsage(procMap);

       // 잠시 대기 후 CPU 사용률 업데이트 (두 번째 스냅샷)
       UpdateProcessCpuUsage(procMap);


	   // 동일한 name 의 프로세스가 여러 개일 경우 CPU 사용율을 모두 합산
	   std::map<std::wstring, double> cpuSumMap;
	   for (const auto& [pid, procInfo] : procMap) {
		   if (procInfo.cpuPercent > 0) {
			   cpuSumMap[procInfo.name] += procInfo.cpuPercent;
		   }
	   }
	   for (auto& [pid, procInfo] : procMap) {
		   if (procInfo.cpuPercent > 0) {
			   procInfo.cpuPercent = cpuSumMap[procInfo.name];
		   }
	   }

   }


   for (const auto& [pid, procInfo] : procMap) {
       result.push_back(procInfo);
   }

   if (args.count(L"sort")) {
       ApplySorting(result, args.at(L"sort"));
   }
   return result;  
}


// 헤더 출력
void PrintHeader(const std::vector<std::wstring>& fields) {
    for (const auto& col : fields) {
        if (col == L"user") std::wcout << std::setw(15) << L"USER";
        else if (col == L"pid") std::wcout << std::setw(8) << L"PID";
        else if (col == L"ppid") std::wcout << std::setw(8) << L"PPID";
        else if (col == L"time") std::wcout << std::setw(8) << L"TIME";
        else if (col == L"cmd") std::wcout << L"\t\t\t\tCMD\t";
        else if (col == L"name") std::wcout << "\t" << L"NAME\t";
        else if (col == L"pri") std::wcout << std::setw(8) << L"PRI";
        else if (col == L"c") std::wcout << std::setw(4) << L"C";
        else if (col == L"stime") std::wcout << std::setw(10) << L"STIME";
    }
    std::wcout << std::endl;
}

// 프로세스 출력
void PrintProcesses(const std::vector<ProcInfo>& procs, const std::vector<std::wstring>& fields) {
    std::wcout << std::fixed << std::setprecision(1);

    for (const auto& proc : procs) {
		for (const auto& col : fields) {
            if (col == L"user") std::wcout << std::setw(15) << proc.user.substr(0, 14);
            else if (col == L"pid") std::wcout << std::setw(8) << proc.pid;
            else if (col == L"ppid") std::wcout << std::setw(8) << proc.ppid;
            else if (col == L"time") std::wcout << std::setw(8) << proc.time;
            else if (col == L"cmd") std::wcout << "\t\t" << proc.cmd << "\t";
            else if (col == L"name") std::wcout << "\t" << proc.name << "\t";
            else if (col == L"pri") std::wcout << std::setw(8) << proc.priority;
            else if (col == L"c") std::wcout << std::setw(4) << std::fixed << std::setprecision(1) << proc.cpuPercent;
            else if (col == L"stime") std::wcout << std::setw(10) << proc.startTime;
        }
		std::wcout << std::endl << std::flush;
        
    }


    
}
// 프로세스 종료

