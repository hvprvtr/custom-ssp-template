/*
 * ssp_load.c  -  горячая (вы)грузка нашего SSP в ЖИВОЙ lsass через
 *                AddSecurityPackage / RemoveSecurityPackage — БЕЗ реестра и
 *                БЕЗ перезагрузки.
 *
 * Зачем: убрать мучительный цикл разработки «правка register.ps1 -> ребут ->
 * проверка -> при сбое откат/восстановление ОС». Пакет грузится НЕ-перманентно
 * (без флага SECPKG_OPTIONS_PERMANENT): в реестр LSA ничего не пишется, поэтому
 * ЛЮБОЙ критический сбой лечится обычной перезагрузкой ВМ — состояние вернётся
 * как было, ничего восстанавливать не нужно.
 *
 * !!! ВНИМАНИЕ: загружает код прямо в lsass.exe. Кривая DLL уронит lsass, и
 *     система уйдёт в принудительный ребут. Пользоваться только на учебной ВМ со
 *     снапшотом. RunAsPPL должен быть выключен (иначе неподписанная DLL не
 *     загрузится). Запускать от администратора (лучше — от SYSTEM, см. ниже).
 *
 * Сборка:  cl /DSECURITY_WIN32 ssp_load.c /link Secur32.lib Advapi32.lib
 *
 * Использование:
 *   ssp_load load   <путь-к-dll> [--ap] [--permanent]   загрузить (по умолч. как SSP)
 *   ssp_load unload [имя-пакета]                         выгрузить (по умолч. CustomSSP)
 *   ssp_load list   [подстрока]                          показать загруженные пакеты
 *
 * Итеративная разработка (без ребута):
 *   ssp_load unload            (снять прежнюю версию — освобождает DLL в lsass)
 *   cmake --build --preset x64-release          (пересобрать)
 *   ssp_load load out\build\x64-release\CustomSSP.dll
 *   ssp_test user:user
 * Если unload не освобождает файл (LSA иногда держит модуль) — собери новую
 * версию под другим именем файла и грузи её, либо ребутни ВМ (это быстро и
 * безопасно, т.к. в реестре ничего нет).
 */
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <stdio.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")

#define DEFAULT_PKG "CustomSSP"

/* Пытаемся включить привилегию (молча игнорируем, если её нет у токена).
 * AddSecurityPackage в ряде конфигураций требует SeTcbPrivilege — её держит
 * только SYSTEM, поэтому при отказе доступа запускай утилиту от SYSTEM. */
static void EnablePriv(const char *name)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    if (LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(tok);
}

/* Короткая расшифровка частых кодов возврата, чтобы не гадать по hex. */
static const char *StatusHint(SECURITY_STATUS st)
{
    switch ((unsigned long)st) {
    case 0x00000000UL: return "SEC_E_OK — успех";
    case 0x80070005UL: return "ACCESS_DENIED — запусти от SYSTEM (см. ниже)";
    case 0x8007007EUL: return "MOD_NOT_FOUND — DLL не найдена или битые зависимости";
    case 0x800700C1UL: return "BAD_EXE_FORMAT — не та разрядность DLL (нужна x64)";
    case 0x8007000BUL: return "BAD_FORMAT — образ повреждён/не DLL";
    case 0x80090302UL: return "UNSUPPORTED_FUNCTION — нет нужного экспорта в DLL";
    case 0x80090304UL: return "INTERNAL_ERROR — LSA отказал (RunAsPPL? подпись? SeTcbPrivilege?)";
    case 0x8009030DUL: return "UNKNOWN_CREDENTIALS";
    case 0xC0000225UL: return "NOT_FOUND — пакет с таким именем не загружен";
    default:           return "(см. winerror.h / ntstatus.h)";
    }
}

/* Регистронезависимый поиск подстроки без зависимости от shlwapi. */
static const char *StrStrIA_local(const char *hay, const char *needle)
{
    size_t nl;
    if (!needle || !*needle) return hay;
    nl = strlen(needle);
    for (; *hay; hay++)
        if (_strnicmp(hay, needle, nl) == 0)
            return hay;
    return NULL;
}

static int DoList(const char *filter)
{
    ULONG        cnt = 0;
    PSecPkgInfoA pkgs = NULL;
    SECURITY_STATUS st;
    ULONG        i, shown = 0;

    st = EnumerateSecurityPackagesA(&cnt, &pkgs);
    if (st != SEC_E_OK || !pkgs) {
        printf("EnumerateSecurityPackages: 0x%08lX  %s\n", (unsigned long)st, StatusHint(st));
        return 1;
    }
    printf("Загружено пакетов: %lu%s%s\n", cnt,
           filter ? "  (фильтр: " : "", filter ? filter : "");
    if (filter) printf(")\n");
    for (i = 0; i < cnt; i++) {
        const char *nm = pkgs[i].Name ? pkgs[i].Name : "(?)";
        if (filter && !StrStrIA_local(nm, filter))
            continue;
        printf("  %-22s cap=0x%08lX maxToken=%lu  %s\n",
               nm, pkgs[i].fCapabilities, pkgs[i].cbMaxToken,
               pkgs[i].Comment ? pkgs[i].Comment : "");
        shown++;
    }
    if (filter && shown == 0)
        printf("  (совпадений нет — пакет не загружен)\n");
    FreeContextBuffer(pkgs);
    return 0;
}

static int DoLoad(const char *path, BOOL asAp, BOOL permanent)
{
    char full[MAX_PATH];
    DWORD r;
    SECURITY_PACKAGE_OPTIONS opt;
    SECURITY_STATUS st;

    r = GetFullPathNameA(path, MAX_PATH, full, NULL);
    if (!r || r >= MAX_PATH) {
        printf("[!] не могу разрешить путь: %s\n", path);
        return 1;
    }
    if (GetFileAttributesA(full) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] файл не найден: %s\n", full);
        return 1;
    }

    ZeroMemory(&opt, sizeof(opt));
    opt.Size  = sizeof(opt);
    opt.Type  = asAp ? SECPKG_OPTIONS_TYPE_LSA : SECPKG_OPTIONS_TYPE_SSPI;
    opt.Flags = permanent ? SECPKG_OPTIONS_PERMANENT : 0;

    printf("Загружаю %s\n  как: %s%s\n", full,
           asAp ? "LSA/AP (SECPKG_OPTIONS_TYPE_LSA)"
                : "SSP (SECPKG_OPTIONS_TYPE_SSPI)",
           permanent ? "  + PERMANENT (пишется в реестр!)" : "  (не-перманентно, ребут снимет)");

    /* На всякий случай пробуем поднять привилегии, которые может хотеть LSA. */
    EnablePriv("SeTcbPrivilege");
    EnablePriv("SeSecurityPrivilege");

    st = AddSecurityPackageA(full, &opt);
    printf("AddSecurityPackage: 0x%08lX  %s\n", (unsigned long)st, StatusHint(st));
    if (st != SEC_E_OK)
        return 2;

    printf("OK. Проверяю, что пакет виден в списке SSPI:\n");
    DoList(DEFAULT_PKG);
    printf("Проверь исполнение внутри lsass: C:\\custom-ssp\\lsa.log\n");
    return 0;
}

static int DoUnload(const char *name)
{
    SECURITY_STATUS st;
    EnablePriv("SeTcbPrivilege");
    st = DeleteSecurityPackageA((SEC_CHAR *)name);
    printf("DeleteSecurityPackage(%s): 0x%08lX  %s\n",
           name, (unsigned long)st, StatusHint(st));
    return (st == SEC_E_OK) ? 0 : 2;
}

static void Usage(void)
{
    printf(
      "ssp_load — горячая (вы)грузка SSP в lsass без ребута.\n\n"
      "  ssp_load load   <путь-к-dll> [--ap] [--permanent]\n"
      "  ssp_load unload [имя-пакета]        (по умолчанию %s)\n"
      "  ssp_load list   [подстрока]\n\n"
      "По умолчанию грузит как SSP и НЕ-перманентно (ребут ВМ всё снимет).\n"
      "  --ap         грузить в список Authentication Packages (LSA-роль)\n"
      "  --permanent  записать в реестр (переживёт ребут) — использовать осторожно\n\n"
      "Требуется админ; при ACCESS_DENIED запусти от SYSTEM, например:\n"
      "  PsExec64 -s -i ssp_load.exe load C:\\custom-ssp\\out\\build\\x64-release\\CustomSSP.dll\n",
      DEFAULT_PKG);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);   /* не терять вывод при возможном краше */

    if (argc < 2) { Usage(); return 1; }

    if (_stricmp(argv[1], "list") == 0)
        return DoList(argc > 2 ? argv[2] : NULL);

    if (_stricmp(argv[1], "unload") == 0)
        return DoUnload(argc > 2 ? argv[2] : DEFAULT_PKG);

    if (_stricmp(argv[1], "load") == 0) {
        const char *path = NULL;
        BOOL asAp = FALSE, perm = FALSE;
        int i;
        for (i = 2; i < argc; i++) {
            if      (_stricmp(argv[i], "--ap") == 0)        asAp = TRUE;
            else if (_stricmp(argv[i], "--permanent") == 0) perm = TRUE;
            else if (!path)                                 path = argv[i];
        }
        if (!path) { printf("[!] укажи путь к DLL\n\n"); Usage(); return 1; }
        return DoLoad(path, asAp, perm);
    }

    Usage();
    return 1;
}
