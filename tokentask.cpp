// tokentask.cpp : get username of task using SeDebugPrivilege
//

#include <iostream>
#include <Windows.h>
#include <WinBase.h>
#include <WtsApi32.h>
#include <tchar.h>

#pragma comment(lib, "WtsApi32.lib")

BOOL SetPrivilege(HANDLE hToken,      // token handle
    LPCTSTR Privilege,      // Privilege to enable/disable
    BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);


    if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;


    //
    // first pass.  get current privilege setting
    //

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        &tpPrevious,
        &cbPrevious
    );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;


    //
    // second pass.  set privilege based on previous setting
    //

    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;

    if (bEnablePrivilege)
    {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else
    {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
    }


    AdjustTokenPrivileges(hToken,
        FALSE,
        &tpPrevious,
        cbPrevious,
        NULL,
        NULL
    );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
    DWORD dwRet = 0;
    DWORD dwCount = 0;

    CHAR* lpName = NULL;
    CHAR* lpDomain = NULL;
    DWORD dwNameSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE SNU;

    PWTS_PROCESS_INFO ppProcessInfo;

    DWORD dwPID = 0;
    CHAR strUser[256] = { 0 };
    DWORD strLen = 0;

    HANDLE hToken = NULL;


    printf("Input PID : ");
    scanf_s("%d", &dwPID);


    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
        if (GetLastError() == ERROR_NO_TOKEN)
        {
            if (!ImpersonateSelf(SecurityImpersonation))
            {
                printf("ImpersonateSelf fail : 0x%X\n", GetLastError());
                return 0;
            }


            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
            {
                printf("Re OpenThreadToken fail : 0x%X\n", GetLastError());
                return 0;
            }
        }
        else
        {
            printf("OpenThreadToken fail : 0x%X\n", GetLastError());
            return 0;
        }
    }


    // enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
    {
        printf("SetPrivilege fail : 0x%X\n", GetLastError());
        return 0;
    }


    if (WTSEnumerateProcesses(WTS_CURRENT_SERVER, 0, 1, &ppProcessInfo, &dwRet))
    {
        for (dwCount = 0; dwCount < dwRet; dwCount++)
        {
            if (ppProcessInfo[dwCount].ProcessId == dwPID)
            {
                if (!LookupAccountSid(NULL, ppProcessInfo[dwCount].pUserSid, NULL, &dwNameSize, NULL, &dwDomainSize, &SNU))
                {
                    if (dwNameSize != 0)
                    {
                        lpName = (CHAR*)VirtualAlloc(NULL, dwNameSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                        if (!lpName)
                        {
                            printf("lpName VirtualAlloc fail : 0x%X\n", GetLastError());
                        }
                    }

                    if (dwDomainSize != 0)
                    {
                        lpDomain = (CHAR*)VirtualAlloc(NULL, dwDomainSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                        if (!lpDomain)
                        {
                            printf("lpDomain VirtualAlloc fail : 0x%X\n", GetLastError());
                        }
                    }


                    if (!LookupAccountSidA(NULL, ppProcessInfo[dwCount].pUserSid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SNU))
                    {
                        DWORD dwResult = GetLastError();
                        if (dwResult == ERROR_NONE_MAPPED)
                        {
                            strncpy_s(strUser, "NONMAPPED", strLen);
                        }
                        else
                        {
                            strncpy_s(strUser, "ERROR", strLen);
                        }
                    }
                    else
                    {
                        strncpy_s(strUser, lpName, strLen);
                    }
                }

                printf("User Name : %s\\%s\n", lpDomain, lpName);

                if (lpName)     VirtualFree(lpName, 0, MEM_RELEASE);
                if (lpDomain)   VirtualFree(lpDomain, 0, MEM_RELEASE);

                break;
            }
        }
    }
    else
    {
        printf("[*ERRROR* - *ERROR*]");
    }


    // Free
    if (ppProcessInfo) WTSFreeMemory(ppProcessInfo);


    // disable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, FALSE))
    {
        printf("SetPrivilege fail : 0x%X\n", GetLastError());
        return 0;
    }

    return 0;
}
