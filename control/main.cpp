/*++

Module Name:

    main.cpp

Abstract:

    Main module for for ps/Ob sample

Notice:

    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
    (http://www.microsoft.com/opensource/licenses.mspx)

    
--*/

#include "pch.h"
#include "common.h"
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fltuser.h>
#include <Windows.h>
#include "../driver/shared.h"
#include "Source.h"
#include <shlwapi.h>
#include <process.h>


using namespace std;
#pragma warning( disable : 4242 )
#pragma warning( disable : 4244 )
#include <Wincrypt.h>

#pragma comment(lib, "Shlwapi.lib")

//#define threadCount 1

char* HashMD5(char* data, DWORD* result)
{
    DWORD dwStatus = 0;
    DWORD cbHash = 16;
    UINT i = 0;
    HCRYPTPROV cryptProv;
    HCRYPTHASH cryptHash;
    BYTE hash[16];
    char* hex = "0123456789abcdef";
    char* strHash;
    strHash = (char*)malloc(500);
    ZeroMemory(strHash, 500);
    if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        *result = dwStatus;
        return NULL;
    }
    if (!CryptCreateHash(cryptProv, CALG_MD5, 0, 0, &cryptHash))
    {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %d\n", dwStatus);
        CryptReleaseContext(cryptProv, 0);
        *result = dwStatus;
        return NULL;
    }
    if (!CryptHashData(cryptHash, (BYTE*)data, (DWORD)strlen(data), 0))
    {
        dwStatus = GetLastError();
        printf("CryptHashData failed: %d\n", dwStatus);
        CryptReleaseContext(cryptProv, 0);
        CryptDestroyHash(cryptHash);
        *result = dwStatus;
        return NULL;
    }
    if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hash, &cbHash, 0))
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
        CryptReleaseContext(cryptProv, 0);
        CryptDestroyHash(cryptHash);
        *result = dwStatus;
        return NULL;
    }
    for (i = 0; i < cbHash; i++)
    {
        strHash[i * 2] = hex[hash[i] >> 4];
        strHash[(i * 2) + 1] = hex[hash[i] & 0xF];
    }
    CryptDestroyHash(cryptHash);
    CryptReleaseContext(cryptProv, 0);
    return strHash;
}


#include <Psapi.h>
#include <algorithm>

std::string window_title;
std::string search_for;

BOOL CALLBACK EnumWindowCallback(HWND hWindow, LPARAM param)
{
    UNREFERENCED_PARAMETER(param);
    if (IsWindow(hWindow) == TRUE)
    {
        DWORD pid = 0;

        if (GetWindowThreadProcessId(hWindow, &pid) != 0)
        {
            HANDLE hProcess;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (hProcess != 0)
            {
                std::string path;
                CHAR name[MAX_PATH];
                GetModuleFileNameExA(hProcess, NULL, name, sizeof(name) / sizeof(CHAR));
                path = name;
                unsigned int slash = (unsigned int)path.find_last_of('\\');
                if (slash != std::string::npos) {
                    std::string proc_name = path.substr((size_t)slash + 1, path.length());
                    cout << proc_name << endl;
                    std::transform(proc_name.begin(), proc_name.end(), proc_name.begin(), ::tolower);
                    if (proc_name == search_for)
                    {
                        CHAR finalTitle[MAX_PATH];
                        ZeroMemory(finalTitle, sizeof(finalTitle));
                        SendMessageA(hWindow, WM_GETTEXT, (WPARAM)sizeof(CHAR) / sizeof(MAX_PATH), (LPARAM)finalTitle);
                        finalTitle[MAX_PATH - 1] = '\0';
                        window_title = finalTitle;
                        return FALSE;
                    }
                }
            }
        }
    }
    return TRUE;
};

const char* __stdcall GetWinTitleByProcessName(const char* title)
{
    search_for = title;
    std::transform(search_for.begin(), search_for.end(), search_for.begin(), ::tolower);
    if (EnumWindows((WNDENUMPROC)EnumWindowCallback, 0) == FALSE)
    {
        return window_title.c_str();
    }

    return "NOTFOUND";
}
#define MAXPATH 1024
BOOL GetWin32FileName(const wchar_t* pszNativeFileName, wchar_t* pszWin32FileName)
{
    BOOL bFound = FALSE;

    // Translate path with device name to drive letters.
    wchar_t szTemp[MAXPATH];
    szTemp[0] = '\0';

    if (GetLogicalDriveStringsW(MAXPATH - 1, szTemp))
    {
        wchar_t szName[MAXPATH];
        ZeroMemory(szName, MAXPATH);
        wchar_t szDrive[MAXPATH] = (L" :");
        wchar_t* p = szTemp;

        for (int i = 0; i < 25; i++)
        {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDeviceW(szDrive, szName, MAXPATH))
            {
                size_t uNameLen = wcslen(szName);

                if (uNameLen < MAXPATH - 1)
                {
                    bFound = _wcsnicmp(pszNativeFileName, szName, uNameLen) == 0
                        && *(pszNativeFileName + uNameLen) == _T('\\');

                    if (bFound)
                    {
                        // Replace device path with DOS path
                        wsprintfW(pszWin32FileName,                            
                            (L"%s%s"),
                            szDrive,
                            pszNativeFileName + uNameLen);
                        return bFound;
                    }
                }
            }
            // Go to the next NULL character.
            while (*p++);
        } //while (!bFound && *p);
    }

    return(bFound);
}

//
// PrintUsage
//

void TcPrintUsage()
{
    puts ("Usage:");
    puts ("");
    puts("    ObCallbackTestCtrl.exe -install -name NameofExe -reject NameofExe -uninstall -deprotect [-?] h");
    puts("     -install        install driver");
    puts("     -uninstall      uninstall driver");
    puts("     -name NameofExe    protect/filter access to NameofExe");
    puts("     -reject NameofExe    prevents execution of NameofExe");
    puts("     -deprotect      unprotect/unfilter");
}

DWORD getParentPID(DWORD pid)
{
    HANDLE h = NULL;
    PROCESSENTRY32 pe = { 0 };
    DWORD ppid = 0;
    pe.dwSize = sizeof(PROCESSENTRY32);
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(h, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(h, &pe));
    }
    CloseHandle(h);
    return (ppid);
}

int getProcessName(DWORD pid, PWCHAR fname, DWORD sz)
{
    HANDLE h = NULL;
    int e = 0;
    h = OpenProcess
    (
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (h)
    {
        if (GetModuleFileNameEx(h, NULL, fname, sz) == 0)
            e = GetLastError();
        CloseHandle(h);
    }
    else
    {
        e = GetLastError();
    }
    return (e);
}

HANDLE GetProcessByName(PCWSTR name)
{
    DWORD pid = 0;

    // Create toolhelp snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (wstring(process.szExeFile) == wstring(name))
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    // Not found


    return NULL;
}

int GetProcessIDByName(PCWSTR name)
{
    DWORD pid = 0;

    // Create toolhelp snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (wstring(process.szExeFile) == wstring(name))
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return pid;// OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    // Not found


    return -1;
}

//
// wmain()
//
typedef struct _arg
{
    HANDLE hNamedEvent;
    TD_PROTECTNAME_INPUT ProtectNameCallbackInput;
    ULONG64 A;
}arg;
CRITICAL_SECTION pcs;
void trd(void* a)
{
    arg *arg1 = (arg*)a;
    //DWORD bytesR;
  arg1->ProtectNameCallbackInput.Operation = TDProtectName_Reject;
  arg1->ProtectNameCallbackInput.PID = (HANDLE)arg1->A;
    HANDLE hd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)arg1->A);
    if (hd != NULL)
    {
        DWORD par = getParentPID((DWORD)arg1->A);
        wchar_t ch[1024], ch2[1024], ch3[1024];
        GetProcessImageFileNameW(hd, ch, 1024);
        CloseHandle(hd);
        GetWin32FileName(ch, ch2);
        getProcessName(par, ch3, 1024);
      //  _putws(ch2);
        //_putws(ch3);
        BOOL bc = (WrIsSignedExeFile(ch2));

        BOOL bp = (WrIsSignedExeFile(ch3));
        
        if (StrStrIW(ch2, L"WrObCallbCr") == NULL && StrStrIW(ch3, L"WrObCallbCr") == NULL)
        {
            //if((!bc || bp) || (StrStrIW(ch2, L"WrObCallbCr") != NULL || StrStrIW(ch3, L"WrObCallbCr") != NULL) ? "OK" : "B");
            //

            arg1->ProtectNameCallbackInput.Operation = ((bc && !bp)? TDProtectName_Reject : TDProtectName_Protect);

            puts((bc && !bp) ? "True" : "FALSE");
            /*if (arg1->ProtectNameCallbackInput.Operation == TDProtectName_Reject)
            {
                printf("%llu %llu\n", (DWORD64)arg1->ProtectNameCallbackInput.PID, arg1->A);
                _putws(ch2);
                _putws(ch3);
            }   */         

     }
           
           
            
        
    }    
    if (DeviceIoControl(
        TcDeviceHandle,
        TD_IOCTL_UNPROTECT_CALLBACK,
        &arg1->ProtectNameCallbackInput,
        sizeof(arg1->ProtectNameCallbackInput),
        NULL,
        0,
        NULL,
        NULL
    ))
    {

    }

}
int _cdecl
wmain (
    _In_ int argc,
    _In_reads_(argc) LPCWSTR argv[]
)
{
    int ExitCode = ERROR_SUCCESS;
    InitializeCriticalSection(&pcs);
    wchar_t *message = (wchar_t*)malloc(14);
    if (message != NULL)
    {
        ZeroMemory(message, sizeof(message));
        DWORD bytesR = 0;
        TD_PROTECTNAME_INPUT ProtectNameCallbackInput = { 0 };
        ProtectNameCallbackInput.Operation = TDProtectName_Reject;
        //ProtectNameCallbackInput.PID = GetCurrentProcessId();
//TcProcessName(TDProtectName_Reject);
        TcDeviceHandle = CreateFile(
            TD_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

       // wprintf(L"%d\n",  GetLastError());
        //(void)getchar();
        ULONG64 A = 0;
        HANDLE hNamedEvent = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\WRObCallback2");
     //   wprintf(L"%d\n", GetLastError());
        if (DeviceIoControl(
            TcDeviceHandle,
            TD_IOCTL_PROTECT_NAME_CALLBACK,
            NULL,
            0,
            &A,
            8,
            &bytesR,
            NULL
        ))
        {
           
        }
      /*  if (DeviceIoControl(
            TcDeviceHandle,
            TD_IOCTL_UNPROTECT_CALLBACK,
            &ProtectNameCallbackInput,
            sizeof(ProtectNameCallbackInput),
            NULL,
            0,
            NULL,
            NULL
        ))
        {

        }*/
        
        while (TRUE)
        {
            A = 0;
            ResetEvent(hNamedEvent);
            WaitForSingleObject(hNamedEvent, INFINITE);
          //  arg arg1;
            /*BOOL Result = */   
            if (DeviceIoControl(
                TcDeviceHandle,
                TD_IOCTL_PROTECT_NAME_CALLBACK,
                NULL,
                0,
                &A,
                8,
                &bytesR,
                NULL
            ))
            {
            
                //  EnterCriticalSection(&pcs);
                  //LeaveCriticalSection(&pcs);
                arg arg1;
                arg1.hNamedEvent = hNamedEvent;
                arg1.ProtectNameCallbackInput = ProtectNameCallbackInput;
                arg1.A = A;
                arg1.ProtectNameCallbackInput.PID = (HANDLE)A;
               // printf("%llu\n", A);
              
            /*HANDLE hThread = (HANDLE) */ //_beginthread(trd, 0, &arg1);
                trd(&arg1);
            //   BOOL bAl = trd(&arg1);               
              // puts(bAl ? "OK" : "Noooo");
               //arg1.ProtectNameCallbackInput.Operation = bAl ? TDProtectName_Protect : TDProtectName_Reject;
           //   WaitForSingleObject(hThread, INFINITE);     // wait until the thread has finished
             //   WaitForSingleObject(hNamedEvent, INFINITE);
            }
          //  ProtectNameCallbackInput.Operation = TDProtectName_Protect;
          

                //  WaitForSingleObject(hNamedEvent, INFINITE);

             //   wprintf(L"%llu %d %d\n", A, bytesR, GetLastError());
                
          
         //   (void)getchar();

          //  
            /* ProtectNameCallbackInput.PID = (HANDLE)A;
                
                ProtectNameCallbackInput.Operation = TDProtectName_Reject; 
                wprintf(L"%llu %d\n",  A, GetLastError());
            if (DeviceIoControl(
                TcDeviceHandle,
                TD_IOCTL_UNPROTECT_CALLBACK,
                &ProtectNameCallbackInput,
                sizeof(ProtectNameCallbackInput),
                NULL,
                0,
                NULL,
                NULL
            ))
            {

            }*/
            //wprintf(L"%llu %d\n", A, GetLastError());

            //if(Result>=0)
            
            
               // break;
        } 
       // CloseHandle(hNamedEvent);
    }
    CloseHandle(TcDeviceHandle);
   

    (void)getchar();
    //enumWindowsProc((HWND)Handle, NULL);
   

    if (argc > 3)
    {
        const wchar_t * arg = argv[1];
        char data[500];
        memset(data, 0, 500);
        strcpy_s(data, 500, (char*)argv[0]);
        strcat_s(data, 500, (char*)argv[1]);
        strcat_s(data, 500, (char*)argv[2]);
        strcat_s(data, 500, (char*)argv[3]);
        DWORD r = 0;
        char* hash=HashMD5(data, &r);
        cout << hash << endl;
        if(r>-100)
        exit(0);
        // initialize globals and logging
        if (!TcInitialize()) {
            puts("Initialization failed - program exiting");
            ExitCode = ERROR_FUNCTION_FAILED;
            goto Exit;
        }

        if (0 == wcscmp (arg, L"-install")) {
            TcInstallDriver();
        } else
        if (0 == wcscmp (arg, L"-uninstall")) {
            TcUninstallDriver();
        } else
        if ((0 == wcscmp (arg, L"-?")) || (0 == wcscmp (arg, L"-h")) || (0 == wcscmp (arg, L"-help"))) {
            TcPrintUsage();
        } else
        if (0 == wcscmp (arg, L"-deprotect")) {
            TcRemoveProtection();
        } else
        if (0 == wcscmp (arg, L"-name")) {
            TcProcessName (TDProtectName_Protect);
        } else
        if (0 == wcscmp (arg, L"-reject")) {
            TcProcessName (TDProtectName_Reject);
        } else	{
			puts ("Unknown command!");
			TcPrintUsage();
        }
        
    }
    else
    {
        TcPrintUsage();
    }
  

Exit:

    if (!TcUnInitialize()) {
        puts("UnInitialization failed");
        ExitCode = ERROR_FUNCTION_FAILED;
    }

    return ExitCode;
}



//
// TcRemoveProtection
//

BOOL TcRemoveProtection ()
{
    BOOL ReturnValue = FALSE;

    LOG_INFO(_T("TcRemoveProtection: Entering"));


    //
    // Open a handle to the device.
    //

    ReturnValue = TcOpenDevice();
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (_T("TcOpenDevice failed"));
        goto Exit;
    }


    //
    // Send the command to the driver
    //
    ReturnValue = TcUnprotectCallback();
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (_T("TcUnprotectCallback failed"));
        goto Exit;
    }

Exit:

    //
    // Close our handle to the device.
    //

    ReturnValue = TcCloseDevice();
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (_T("TcCloseDevice failed"));
    }
   

    LOG_INFO(_T("TcRemoveProtection: Exiting"));

    return ReturnValue;
}


//
// TcProcessName
//

BOOL TcProcessName(
    _In_ ULONG ulOperation
)
{
    BOOL ReturnValue = FALSE;
    

   // PCWSTR pwProcessName = NULL;

    LOG_INFO(L"TcProcessName: Entering");


    //
    // Parse command line.
    //
    // argv[1] is "-name" so starting from arg #2 that should be the process name to protect
    //

  

    //pwProcessName = argv[2];

  


    LOG_INFO(L"Ready to copy process name");
   // LOG_INFO(L"Name to pass to driver   %ls", pwProcessName);


    //
    // Open a handle to the device.
    //

    ReturnValue = TcOpenDevice();
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (L"TcProcessName: TcOpenDevice failed");
        goto Exit;
    }


    //
    // Send process name to protect and the command to the driver
    //
    ReturnValue = TcProcessNameCallback(ulOperation);
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (L"TcProcessName: TcProcessNameCallback failed");
        goto Exit;
    }

Exit:

    //
    // Close our handle to the device.
    //

    ReturnValue = TcCloseDevice();
    if (ReturnValue != TRUE)
    {
        LOG_INFO_FAILURE (L"TcProtectProcess: TcCloseDevice failed");
    }
   

    LOG_INFO(L"TcProtectProcess: Exiting");

    return ReturnValue;
}



//
// TcInstallDriver  - installs the kernel driver
//

BOOL TcInstallDriver ()
{
    BOOL bRC = TRUE;

    LOG_INFO(L"TcInstallDriver: Entering");
    BOOL Result = TcLoadDriver();

    if (Result != TRUE)
    {
        LOG_ERROR (L"TcLoadDriver failed, exiting");
        bRC = FALSE;
        goto Exit;
    }

Exit:

    LOG_INFO(L"TcInstallDriver: Exiting");
    return bRC;
}


//
// TcUninstallDriver  - uninstalls the kernel driver
//

BOOL TcUninstallDriver ()
{
    BOOL bRC = TRUE;

    LOG_INFO(L"TcUninstallDriver: Entering");
    BOOL Result = TcUnloadDriver();

    if (Result != TRUE)
    {
        LOG_ERROR (L"TcUnloadDriver failed, exiting");
        bRC = FALSE;
        goto Exit;
    }

Exit:

    LOG_INFO(L"TcUninstallDriver: Exiting");
    return bRC;
}


//
// TcInitialize
//

BOOL bLoggingInitialized = FALSE;

BOOL TcInitialize  ()
{

    BOOL Result = TcInitializeGlobals();
    if (Result != TRUE)
    {
        LOG_ERROR (L"TcInitializeGlobals failed, exiting");
        return FALSE;
    }

    LOG_INFO(L"TcInitialize: Entering");
    return TRUE;

}

//
// TcUnInitialize
//

BOOL TcUnInitialize()
{
    if (TcCleanupSCM() == FALSE){
        LOG_ERROR (L"TcUnInitialize failed cleanup of SCM");
    }
    return TRUE;
}
