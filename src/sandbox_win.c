// SPDX-License-Identifier: MIT
#include "sandbox.h"

#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// after windows.h
#include <psapi.h>
#include <stdlib.h>

// ---- job object -------------------------------------------------------------
// No child processes, a cap on private memory, killed if anything goes
// wrong, and no access to the desktop, clipboard or global atoms.
static int enter_job(uint64_t headroom)
{
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job)
        return -1;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = {0};
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                           JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                                           JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    lim.BasicLimitInformation.ActiveProcessLimit = 1;
    if (headroom) {
        // Committed private memory now (all of guest RAM is committed)
        // plus headroom.
        PROCESS_MEMORY_COUNTERS_EX pmc = {.cb = sizeof pmc};
        if (!K32GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc,
                                     sizeof pmc)) {
            CloseHandle(job);
            return -1;
        }
        lim.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        lim.ProcessMemoryLimit = pmc.PrivateUsage + (SIZE_T)headroom;
    }
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {
        .UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                               JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                               JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                               JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                               JOB_OBJECT_UILIMIT_WRITECLIPBOARD};
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof lim) ||
        !SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof ui) ||
        !AssignProcessToJobObject(job, GetCurrentProcess())) {
        CloseHandle(job);
        return -1;
    }
    // A handle must stay open for the life of the process (closing the last
    // one kills us: KILL_ON_JOB_CLOSE), but it shouldn't be one that could
    // lift the limits again. Swap it for a query-only handle, kept forever.
    HANDLE weak;
    if (!DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &weak, JOB_OBJECT_QUERY,
                         FALSE, DUPLICATE_CLOSE_SOURCE))
        return -1;
    return 0;
}

// ---- process mitigation policies ---------------------------------------------
static int mitigations(char *failed, size_t failed_len)
{
    int rc = 0;
    failed[0] = 0;
#define POLICY(kind, field_setup)                                                            \
    do {                                                                                     \
        PROCESS_MITIGATION_##kind##_POLICY pol;                                              \
        memset(&pol, 0, sizeof pol);                                                         \
        field_setup;                                                                         \
        if (!SetProcessMitigationPolicy(Process##kind##Policy, &pol, sizeof pol)) {          \
            size_t used = strlen(failed);                                                    \
            snprintf(failed + used, failed_len - used, "%s" #kind, used ? "," : "");         \
            rc = -1;                                                                         \
        }                                                                                    \
    } while (0)
    // ProcessDynamicCodePolicy -> PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, etc.
#define PROCESS_MITIGATION_DynamicCode_POLICY PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
#define PROCESS_MITIGATION_StrictHandleCheck_POLICY PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
#define PROCESS_MITIGATION_ExtensionPointDisable_POLICY PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
#define PROCESS_MITIGATION_ImageLoad_POLICY PROCESS_MITIGATION_IMAGE_LOAD_POLICY
#define PROCESS_MITIGATION_Signature_POLICY PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
#define PROCESS_MITIGATION_FontDisable_POLICY PROCESS_MITIGATION_FONT_DISABLE_POLICY
#define PROCESS_MITIGATION_SystemCallDisable_POLICY PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    POLICY(DynamicCode, pol.ProhibitDynamicCode = 1);
    POLICY(StrictHandleCheck,
           (pol.RaiseExceptionOnInvalidHandleReference = 1, pol.HandleExceptionsPermanentlyEnabled = 1));
    POLICY(ExtensionPointDisable, pol.DisableExtensionPoints = 1);
    POLICY(ImageLoad, (pol.NoRemoteImages = 1, pol.NoLowMandatoryLabelImages = 1,
                       pol.PreferSystem32Images = 1));
    POLICY(Signature, pol.MicrosoftSignedOnly = 1);
    POLICY(FontDisable, pol.DisableNonSystemFonts = 1);
    POLICY(SystemCallDisable, pol.DisallowWin32kSystemCalls = 1);
#undef POLICY
    return rc;
}

// ---- token: no privileges, Low integrity ---------------------------------
static int restrict_token(void)
{
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT, &tok))
        return -1;
    int rc = -1;
    DWORD len = 0;
    GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &len);
    TOKEN_PRIVILEGES *privs = len ? malloc(len) : nullptr;
    if (!privs || !GetTokenInformation(tok, TokenPrivileges, privs, len, &len))
        goto out;
    for (DWORD i = 0; i < privs->PrivilegeCount; i++)
        privs->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    if (!AdjustTokenPrivileges(tok, FALSE, privs, 0, nullptr, nullptr) ||
        GetLastError() != ERROR_SUCCESS)
        goto out;

    // S-1-16-4096: Low mandatory level. Low can't write to anything at
    // Medium (the user's files, registry, other processes).
    SID_IDENTIFIER_AUTHORITY ml = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID low = nullptr;
    if (!AllocateAndInitializeSid(&ml, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &low))
        goto out;
    TOKEN_MANDATORY_LABEL tml = {.Label = {.Sid = low, .Attributes = SE_GROUP_INTEGRITY}};
    if (SetTokenInformation(tok, TokenIntegrityLevel, &tml,
                            sizeof tml + GetLengthSid(low)))
        rc = 0;
    FreeSid(low);
out:
    free(privs);
    CloseHandle(tok);
    return rc;
}

int sandbox_enter(const sandbox_cfg *cfg, char *report, size_t report_len)
{
    char failed[160];
    if (enter_job(cfg->mem_headroom))
        return -1;
    if (mitigations(failed, sizeof failed)) {
        if (report)
            snprintf(report, report_len, "sandbox: mitigation policies failed: %s", failed);
        return -1;
    }
    if (restrict_token())
        return -1;
    if (cfg->start_threads) // nothing here stops new threads
        cfg->start_threads(cfg->ctx);
    if (report)
        snprintf(report, report_len,
                 "sandbox: job=on mitigations=on privileges=none integrity=low");
    return 0;
}
