//
// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: BSD-2-Clause
//

#include <iostream>
#include <string>
#include <codecvt>
#include <locale>
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <Wincrypt.h>

extern unsigned char DummyDll[121344];

#define COMPUTER_NAME_FIXED_WORD "DESKTOPX"
#define COMPUTER_NAME_RANDOM_WORD "XXXXXXX"
#define COMPUTER_NAME_RANDOM_CHARS_SET "0123456789ABCDEFGHZKLMNPORSTWXH"

#define EMOLOAD_MAGIC 0xDEADBEEF

#pragma pack(push,1)
typedef struct {
    DWORD Magic;
    DWORD Epoch;
    DWORD SerialNumber;
    DWORD ComputerNameSize;
    DWORD DllSize;
} EMOLOAD, * PEMOLOAD;
#pragma pack(pop)

#define COMPUTER_NAME_FIXED_WORD "DESKTOPX"
#define COMPUTER_NAME_RANDOM_WORD "XXXXXXX"
#define COMPUTER_NAME_RANDOM_CHARS_SET "0123456789ABCDEFGHZKLMNPORSTWXH"

typedef BOOL(WINAPI* DllMain_t)(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved);

#pragma pack(push,1)
typedef struct {
    PCHAR pID;              // "DESKTOPXHO47NFZ_1E62B7B" for computer name "DESKTOP-HO47NFZ" and C:\ volume serial number 0x1E62B7B
    PBYTE pECK1;
    ULONG64 ECK1_Size;      // Always 0x48
    PBYTE pECS1;
    ULONG64 ECS1_Size;      // Always 0x48
    ULONG Unk1;
    ULONG Unk2;
    ULONG64 Unk3;
    HANDLE hUnloadEvent;
    UCHAR Unk4[1024];
} EMOTET_LOADER_DATA;
#pragma pack(pop)

unsigned char ECS1_Epoch4[72] = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x40, 0x5F, 0x74, 0xB6, 0xC4, 0xD8, 0xDC, 0x0C,
    0x3D, 0x1F, 0x06, 0x7A, 0x37, 0xDC, 0xB9, 0xF9, 0xB7, 0xBD, 0x5E, 0x8A, 0x2F, 0xA6, 0xA1, 0xF2,
    0x0F, 0xA1, 0x79, 0x0D, 0x14, 0xE5, 0xF5, 0x31, 0xE8, 0xB0, 0x0A, 0x1E, 0x3C, 0x8B, 0x3F, 0x7B,
    0x90, 0x1D, 0x26, 0x26, 0x31, 0x86, 0x65, 0x7C, 0x1A, 0xAD, 0xD9, 0xC3, 0x5C, 0xAC, 0x48, 0xF0,
    0x60, 0x87, 0x18, 0xD9, 0x74, 0x3C, 0x58, 0xF9
};
unsigned char ECK1_Epoch4[72] = {
    0x45, 0x43, 0x4B, 0x31, 0x20, 0x00, 0x00, 0x00, 0xF3, 0xA3, 0x35, 0xB5, 0x0E, 0x2E, 0x2B, 0xF4,
    0x35, 0x56, 0xCD, 0x0A, 0x4C, 0x29, 0x3E, 0x7C, 0xF1, 0x10, 0xDD, 0xCB, 0xB0, 0x4F, 0x20, 0xB3,
    0xFA, 0x02, 0x20, 0xCE, 0x4C, 0xB6, 0x0C, 0x1E, 0x44, 0x96, 0xBE, 0xB4, 0x0E, 0xE6, 0xC9, 0x5B,
    0x9A, 0xBD, 0x4E, 0xBD, 0x9D, 0x8F, 0xCF, 0xE0, 0x10, 0x5B, 0x34, 0x4C, 0x82, 0x04, 0x26, 0x02,
    0xD3, 0xBA, 0xAC, 0xF1, 0xFB, 0x9F, 0x2C, 0x76
};

unsigned char ECS1_Epoch5[72] = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0xF4, 0x2F, 0x1A, 0x83, 0x36, 0x1A, 0x27, 0x51,
    0x8C, 0x24, 0xF2, 0xCA, 0xA8, 0xEC, 0x85, 0xAE, 0x52, 0x59, 0x51, 0x75, 0x48, 0x94, 0x06, 0x70,
    0x02, 0x73, 0xAA, 0xE8, 0x9A, 0xC4, 0x28, 0x7B, 0x56, 0x09, 0x0F, 0xBC, 0x08, 0x7B, 0x80, 0x21,
    0x7A, 0xA6, 0x28, 0x7E, 0x96, 0x45, 0xB9, 0xC3, 0xC3, 0x5C, 0x26, 0x74, 0xCF, 0xD8, 0xBE, 0xA2,
    0x85, 0x1F, 0x7E, 0xA7, 0xA8, 0x2D, 0x95, 0x34
};
unsigned char ECK1_Epoch5[72] = {
    0x45, 0x43, 0x4B, 0x31, 0x20, 0x00, 0x00, 0x00, 0xD8, 0x35, 0x93, 0xD7, 0x63, 0x8B, 0x50, 0xC5,
    0xDF, 0xCD, 0xE1, 0x69, 0xF9, 0xB1, 0x36, 0x00, 0x9B, 0x9B, 0x54, 0x3B, 0x16, 0x36, 0xA2, 0x5D,
    0x44, 0x2E, 0xB2, 0x38, 0x30, 0xD8, 0x47, 0x36, 0x2E, 0xB8, 0xD2, 0xF4, 0x8B, 0x6A, 0xC8, 0xD8,
    0x4C, 0x7A, 0x45, 0x44, 0x1A, 0x06, 0xFA, 0x8F, 0x38, 0xBE, 0xDA, 0xFB, 0x00, 0x96, 0x9C, 0x84,
    0x2C, 0xCE, 0x1E, 0x36, 0x80, 0x24, 0x50, 0x96
};



PVOID ReadFileData(
    __in std::string FilePath,
    __out PDWORD pFileSize
)
{
    HANDLE hFile = CreateFileA(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD FileSizeHigh = 0;
    DWORD FileSize = GetFileSize(hFile, &FileSizeHigh);
    if (FileSize == INVALID_FILE_SIZE || FileSizeHigh)
    {
        CloseHandle(hFile);
        return NULL;
    }

    PVOID FileData = VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!FileData)
    {
        CloseHandle(hFile);
        return NULL;
    }

    *pFileSize = 0;

    if (!ReadFile(hFile, FileData, FileSize, pFileSize, NULL) || *pFileSize != FileSize)
    {
        VirtualFree(FileData, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    return FileData;
}

BOOL WriteFileData(
    __in std::string FilePath,
    __in PVOID FileData,
    __in DWORD FileSize
)
{
    HANDLE hFile = CreateFileA(FilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD Written = 0;

    if (!WriteFile(hFile, FileData, FileSize, &Written, NULL) || Written != FileSize)
    {
        CloseHandle(hFile);
        DeleteFileA(FilePath.c_str());
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

void FreeFileData(
    __in PVOID FileData
)
{
    VirtualFree(FileData, 0, MEM_RELEASE);
}

std::string WriteFileDataWithRandomName(
    __in PVOID FileData,
    __in DWORD FileSize
)
{
    char FileName[sizeof("XXXXXXXX.dll")];
    snprintf(FileName, sizeof(FileName), "%08X.dll", (rand() & 0xFFFF) | ((rand() & 0xFFFF) << 16));

    if (!WriteFileData(FileName, FileData, FileSize)) {
        return std::string();
    }

    return std::string(FileName);
}

std::string GetSha256(
    __in PVOID Data,
    __in DWORD Size
)
{
    HCRYPTPROV hProv = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return std::string();
    }

    HCRYPTHASH hSha256 = NULL;

    if (!CryptCreateHash(hProv, CALG_SHA_256, NULL, 0, &hSha256)) {
        CryptReleaseContext(hProv, 0);
        return std::string();
    }

    if (!CryptHashData(hSha256, (const BYTE*)Data, Size, 0)) {
        CryptDestroyHash(hSha256);
        CryptReleaseContext(hProv, 0);
        return std::string();
    }

    DWORD Sha256Size = 0, ParamSize = sizeof(Sha256Size);

    if (!CryptGetHashParam(hSha256, HP_HASHSIZE, (BYTE*)&Sha256Size, &ParamSize, 0) || ParamSize != sizeof(Sha256Size)) {
        CryptDestroyHash(hSha256);
        CryptReleaseContext(hProv, 0);
        return std::string();
    }

    PBYTE Sha256Hash = (PBYTE)malloc(Sha256Size);
    if (!Sha256Hash) {
        CryptDestroyHash(hSha256);
        CryptReleaseContext(hProv, 0);
        return std::string();
    }

    BOOL b = CryptGetHashParam(hSha256, HP_HASHVAL, Sha256Hash, &Sha256Size, 0);

    CryptDestroyHash(hSha256);
    CryptReleaseContext(hProv, 0);

    if (!b) {
        free(Sha256Hash);
        return std::string();
    }

    std::string Sha256String;

    for (DWORD i = 0; i < Sha256Size; i++)
    {
        char ByteString[sizeof("XX")];
        snprintf(ByteString, sizeof(ByteString), "%02X", Sha256Hash[i]);
        Sha256String += ByteString;
    }

    free(Sha256Hash);
    return Sha256String;
}

std::string GetFileSha256(
    __in std::string FilePath
)
{
    DWORD FileSize = 0;
    PVOID FileData = ReadFileData(FilePath, &FileSize);
    if (!FileData) {
        return std::string();
    }

    std::string Sha256 = GetSha256(FileData, FileSize);
    FreeFileData(FileData);

    return Sha256;
}

PVOID GetSelfData(
    __out PDWORD pFileSize
)
{
    char* SelfPath = nullptr;

    if (_get_pgmptr(&SelfPath)) {
        return NULL;
    }

    return ReadFileData(SelfPath, pFileSize);
}

//
// Given that the input DLL's SHA256 is 3D8F8F406A04A740B8ABB1D92490AFEF2A9ADCD9BEECB13AECF91F53AAC736B4,
// epoch is 5, computer name and the C: volume serial number are random, it transforms the original output
// path "out.exe" to
// "out_3D8F8F406A04A740B8ABB1D92490AFEF2A9ADCD9BEECB13AECF91F53AAC736B4_epoch_5_computer_name_random_serial_random.exe"
//

std::string GenerateOutputPath(
    __in std::string OriginalOutputPath,
    __in std::string DllSha256,
    __in DWORD Epoch,
    __in_opt std::string ComputerName,
    __in_opt DWORD SerialNumber
)
{
    std::string OutputPath = OriginalOutputPath;
    std::string Extension;

    auto pos = OutputPath.find_last_of('.');
    if (pos != std::string::npos) {
        Extension = OutputPath.substr(pos);
        OutputPath.resize(pos);
    }

    OutputPath += "_";
    OutputPath += DllSha256;
    
    OutputPath += "_epoch_";
    OutputPath += std::to_string(Epoch);
    
    if (!ComputerName.empty()) {
        OutputPath += "_computer_name_";
        OutputPath += ComputerName;
    }
    else {
        OutputPath += "_computer_name_random";
    }

    if (SerialNumber) {
        OutputPath += "_serial_";
        char aSerialNumber[sizeof("XXXXXXXX")] = { 0 };
        snprintf(aSerialNumber, sizeof(aSerialNumber), "%08X", SerialNumber);
        OutputPath += aSerialNumber;
    }
    else {
        OutputPath += "_serial_random";
    }

    OutputPath += Extension;
    return OutputPath;
}

//
// Creates an executable bundle with given parameters (Emotet's DLL, epoch, computer name, C: volume serial number)
// and drops it by the resulting path, that incorporates the bundle's parameters
//

BOOL GenerateEmotetLoader(
    __in std::string OutputPath,
    __in std::string DllPath,
    __in DWORD Epoch,
    __in_opt std::string ComputerName,
    __in_opt DWORD SerialNumber
)
{
    DWORD DllSize = 0;
    PVOID DllData = ReadFileData(DllPath, &DllSize);
    if (!DllData) {
        std::cout << "Failed to read " << DllPath << "\n";
        return FALSE;
    }

    std::string DllSha256 = GetSha256(DllData, DllSize);
    OutputPath = GenerateOutputPath(OutputPath, DllSha256, Epoch, ComputerName, SerialNumber);

    DWORD SelfSize = 0;
    PVOID SelfData = GetSelfData(&SelfSize);
    if (!SelfData) {
        FreeFileData(DllData);
        return FALSE;
    }

    DWORD EmoLoadDataSize = SelfSize + sizeof(EMOLOAD) + ComputerName.length() + 1 + DllSize;

    PVOID EmoLoadData = VirtualAlloc(NULL, EmoLoadDataSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!EmoLoadData) {
        FreeFileData(DllData);
        FreeFileData(SelfData);
        return FALSE;
    }

    memcpy(EmoLoadData, SelfData, SelfSize);

    PEMOLOAD EmoLoad = (PEMOLOAD)((PBYTE)EmoLoadData + SelfSize);
    memset(EmoLoad, 0, sizeof(EMOLOAD));

    EmoLoad->Magic = EMOLOAD_MAGIC;
    EmoLoad->Epoch = Epoch;
    EmoLoad->SerialNumber = SerialNumber;

    if (!ComputerName.empty())
    {
        EmoLoad->ComputerNameSize = ComputerName.length() + 1;
        memcpy((PBYTE)EmoLoad + sizeof(EMOLOAD), ComputerName.c_str(), EmoLoad->ComputerNameSize);
    }

    EmoLoad->DllSize = DllSize;
    memcpy((PBYTE)EmoLoad + sizeof(EMOLOAD) + EmoLoad->ComputerNameSize, DllData, DllSize);

    BOOL Result = WriteFileData(OutputPath, EmoLoadData, EmoLoadDataSize);

    if (Result)
    {
        std::cout << "Emotet loader bundle was dropped to " << OutputPath << "\n";
    }
    else
    {
        std::cout << "Failed to drop the Emotet loader bundle to " << OutputPath << "\n";
    }

    VirtualFree(EmoLoadData, 0, MEM_RELEASE);
    FreeFileData(DllData);
    FreeFileData(SelfData);

    return Result;
}



BOOL PatchSection(
    __in MODULEENTRY32* Module,
    __in PVOID SectionData,
    __in DWORD SectionSize,
    __in PUNICODE_STRING CommandLineToPatch,
    __in std::wstring& NewCommandLine
)
{
    BOOL Patched = FALSE;

    __try
    {
        PUNICODE_STRING BaseUnicodeCommandLine = (PUNICODE_STRING)SectionData;
        PUNICODE_STRING FinalBaseUnicodeCommandLine = (PUNICODE_STRING)((PBYTE)BaseUnicodeCommandLine + SectionSize - sizeof(UNICODE_STRING));

        while (BaseUnicodeCommandLine <= FinalBaseUnicodeCommandLine)
        {
            if (!memcmp(BaseUnicodeCommandLine, CommandLineToPatch, sizeof(UNICODE_STRING)))
            {
                BaseUnicodeCommandLine->Buffer = (PWCHAR)NewCommandLine.c_str();
                BaseUnicodeCommandLine->Length = NewCommandLine.length() * sizeof(WCHAR);
                BaseUnicodeCommandLine->MaximumLength = (NewCommandLine.length() + 1) * sizeof(WCHAR);

                std::wcout << Module->szModule << L"!BaseUnicodeCommandLine was patched\n";

                *(PULONG_PTR)&BaseUnicodeCommandLine += sizeof(UNICODE_STRING);
                Patched = TRUE;
                continue;
            }

            ++*(PULONG_PTR)&BaseUnicodeCommandLine;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ;
    }

    return Patched;
}


//
// Emotet modules sometimes check the command line and they may refuse to work
// if the process was started without parameters; additionally, some of them assume
// that the first argument of the command line is the path to the core Emotet
// component, that they try to read.
//
// This function drops a dummy DLL on disk and then it replaces all copies of
// PEB.ProcessParameters.CommandLine found in all DLLs with a fake one:
// "C:\Windows\System32\regsvr32.exe" "xxxxxxxx.dll"
//
// It is especially important to patch kernelbase.dll!BaseUnicodeCommandLine because
// GetCommandLineW returns it; it also patches the command line stored in RTL_USER_PROCESS_PARAMETERS.
//

BOOL PatchCommandLine(
)
{
    std::string DummyPath = WriteFileDataWithRandomName(DummyDll, sizeof(DummyDll));
    if (DummyPath.empty()) {
        return FALSE;
    }

    std::cout << "Emotet dummy DLL was dropped to " << DummyPath << "\n";

    static std::wstring Regsvr32 = L"C:\\Windows\\System32\\regsvr32.exe";
    static std::wstring CommandLine = L"\"C:\\Windows\\System32\\regsvr32.exe\" \"";

    CommandLine += std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(DummyPath);
    CommandLine += L"\"";

    PTEB Teb = (PTEB)__readgsqword(0x30);
    PRTL_USER_PROCESS_PARAMETERS UserParams = Teb->ProcessEnvironmentBlock->ProcessParameters;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DeleteFileA(DummyPath.c_str());
        return FALSE;
    }

    MODULEENTRY32 Module = { 0 };
    Module.dwSize = sizeof(Module);

    if (!Module32First(hSnapshot, &Module)) {
        CloseHandle(hSnapshot);
        DeleteFileA(DummyPath.c_str());
        return FALSE;
    }

    BOOL BaseUnicodeCommandLinePatched = FALSE;

    do
    {
        PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)Module.modBaseAddr;
        PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PCHAR)Module.modBaseAddr + pDosHdr->e_lfanew);
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(pNtHdrs);

        for (WORD SectionIdx = 0; SectionIdx < pNtHdrs->FileHeader.NumberOfSections; SectionIdx++, Section++)
        {
            BaseUnicodeCommandLinePatched |= PatchSection(
                &Module, (PBYTE)Module.modBaseAddr + Section->VirtualAddress, Section->Misc.VirtualSize, &UserParams->CommandLine, CommandLine);
        }
    } while (Module32Next(hSnapshot, &Module));

    CloseHandle(hSnapshot);

    if (!BaseUnicodeCommandLinePatched) {
        std::cout << "Couldn't find kernelbase.dll!BaseUnicodeCommandLine\n";
        DeleteFileA(DummyPath.c_str());
        return FALSE;
    }

    UserParams->CommandLine.Buffer = (PWCHAR)CommandLine.c_str();
    UserParams->CommandLine.Length = CommandLine.length() * sizeof(WCHAR);
    UserParams->CommandLine.MaximumLength = (CommandLine.length() + 1) * sizeof(WCHAR);

    UserParams->ImagePathName.Buffer = (PWCHAR)Regsvr32.c_str();
    UserParams->ImagePathName.Length = Regsvr32.length() * sizeof(WCHAR);
    UserParams->ImagePathName.MaximumLength = (Regsvr32.length() + 1) * sizeof(WCHAR);

    std::wcout << L"Command line was patched to " << CommandLine << L"\n";

    return TRUE;
}


//
// Loads an Emotet module with given parameters; generates random computer name and
// the C: volume serial number if they are not provided
//

BOOL LoadEmotetModule(
    __in std::string DllPath,
    __in DWORD Epoch,
    __in_opt std::string ComputerName,
    __in_opt DWORD SerialNumber
)
{
    bool ComputerNameProvided = !ComputerName.empty(), SerialNumberProvided = !!SerialNumber;
    EMOTET_LOADER_DATA LoaderData = { 0 };

    if (Epoch == 4)
    {
        LoaderData.pECK1 = ECK1_Epoch4;
        LoaderData.ECK1_Size = sizeof(ECK1_Epoch4);
        LoaderData.pECS1 = ECS1_Epoch4;
        LoaderData.ECS1_Size = sizeof(ECS1_Epoch4);
    }
    else
    {
        LoaderData.pECK1 = ECK1_Epoch5;
        LoaderData.ECK1_Size = sizeof(ECK1_Epoch5);
        LoaderData.pECS1 = ECS1_Epoch5;
        LoaderData.ECS1_Size = sizeof(ECS1_Epoch5);
    }

    srand(GetTickCount());

    if (!ComputerName.empty())
    {
        for (int i = 0; i < ComputerName.length(); i++)
        {
            if (ComputerName[i] == '-') {
                ComputerName[i] = 'X';
            }
        }
    }
    else
    {
        CHAR GeneratedComputerName[sizeof(COMPUTER_NAME_FIXED_WORD COMPUTER_NAME_RANDOM_WORD)] = COMPUTER_NAME_FIXED_WORD;

        for (int i = _countof(COMPUTER_NAME_FIXED_WORD) - 1; i < _countof(GeneratedComputerName) - 1; i++)
        {
            GeneratedComputerName[i] = COMPUTER_NAME_RANDOM_CHARS_SET[rand() % (_countof(COMPUTER_NAME_RANDOM_CHARS_SET) - 2)];
        }

        ComputerName = GeneratedComputerName;
    }

    char aSerialNumber[sizeof("XXXXXXXX")] = { 0 };

    if (!SerialNumber) {
        SerialNumber = (rand() & 0xFFFF) | ((rand() & 0xFFFF) << 16);
    }

    snprintf(aSerialNumber, sizeof(aSerialNumber), "%08X", SerialNumber);

    std::cout << "DLL SHA256:......." << GetFileSha256(DllPath) << "\n";
    std::cout << "Epoch:............" << Epoch << "\n";
    std::cout << "Computer name:...." << ComputerName << " (" << (ComputerNameProvided ? "static" : "random") << ")\n";
    std::cout << "Serial:..........." << aSerialNumber << " (" << (SerialNumberProvided ? "static" : "random") << ")\n";

    std::string ID = ComputerName;
    ID += "_";
    ID += aSerialNumber;

    LoaderData.pID = (PCHAR)ID.c_str();
    LoaderData.Unk2 = 0x45c;                // It is always different and it is not a handle; doesn't seem to affect execution

    LoaderData.hUnloadEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!LoaderData.hUnloadEvent) {
        std::cout << "CreateEventW failed with error " << GetLastError() << "\n";
        return FALSE;
    }

    if (!PatchCommandLine()) {
        CloseHandle(LoaderData.hUnloadEvent);
        return FALSE;
    }

    std::cout << "Loading " << DllPath << "...\n";

    // LoadLibraryA call will call DllMain with DLL_PROCESS_ATTACH code (1), that will
    // NOT trigger the module's main functionality

    HMODULE hEmotet = LoadLibraryA(DllPath.c_str());
    if (!hEmotet) {
        std::cout << DllPath << " failed to load, last error: " << GetLastError() << "\n";
        CloseHandle(LoaderData.hUnloadEvent);
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hEmotet;
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PCHAR)hEmotet + pDosHdr->e_lfanew);

    DllMain_t DllMain = (DllMain_t)((PCHAR)hEmotet + pNtHdrs->OptionalHeader.AddressOfEntryPoint);

    std::cout << "Calling DllEntryPoint() in custom mode...\n";

    // Code 100 triggers the main functionality of 64-bit modules

    if (DllMain(hEmotet, 100, &LoaderData))
    {
        std::cout << "DllEntryPoint() returned TRUE\n";
    }
    else
    {
        std::cout << "DllEntryPoint() returned FALSE\n";
    }

    std::cout << "The module may still be running in a separated thread\n";

    // The module returned execution; now let the analyst decide
    // whether to kill the process manually or not

    Sleep(INFINITE);
    return TRUE;
}


PEMOLOAD FindEmoLoadStruct(
    __in PVOID SelfData,
    __in DWORD SelfSize
)
{
    PBYTE Current = (PBYTE)SelfData;
    DWORD CurrentSize = SelfSize;

    while (CurrentSize > sizeof(EMOLOAD))
    {
        PEMOLOAD EmoLoad = (PEMOLOAD)Current;

        if (EmoLoad->Magic == EMOLOAD_MAGIC &&
            (EmoLoad->Epoch == 4 || EmoLoad->Epoch == 5) &&
            CurrentSize >= sizeof(EMOLOAD) + EmoLoad->ComputerNameSize + EmoLoad->DllSize &&
            (EmoLoad->ComputerNameSize ? ((PCHAR)EmoLoad + sizeof(EMOLOAD))[EmoLoad->ComputerNameSize - 1] == 0 : true) &&
            ((PIMAGE_DOS_HEADER)((PCHAR)EmoLoad + sizeof(EMOLOAD) + EmoLoad->ComputerNameSize))->e_magic == IMAGE_DOS_SIGNATURE)
        {
            return EmoLoad;
        }

        Current++;
        CurrentSize--;
    }

    return NULL;
}


//
// Detects if the current executable is a bundle with embedded DLL and parameters
// (epoch, computer name, C: volume serial number); it drops the DLL on disk and
// returns the parameters if it is true
//

BOOL GetEmbeddedData(
    __out std::string& DllPath,
    __out DWORD& Epoch,
    __out std::string& ComputerName,
    __out DWORD& SerialNumber
)
{
    DllPath.clear();
    Epoch = 0;
    ComputerName.clear();
    SerialNumber = 0;

    DWORD SelfSize = 0;
    PVOID SelfData = GetSelfData(&SelfSize);
    if (!SelfData) {
        return FALSE;
    }

    PEMOLOAD EmoLoad = FindEmoLoadStruct(SelfData, SelfSize);
    if (!EmoLoad) {
        FreeFileData(SelfData);
        return FALSE;
    }

    DllPath = WriteFileDataWithRandomName(
        (PBYTE)EmoLoad + sizeof(EMOLOAD) + EmoLoad->ComputerNameSize, EmoLoad->DllSize);
    if (DllPath.empty()) {
        FreeFileData(SelfData);
        return FALSE;
    }

    std::cout << "The embedded DLL was dropped to " << DllPath << "\n";

    if (EmoLoad->ComputerNameSize) {
        ComputerName = (PCHAR)((PBYTE)EmoLoad + sizeof(EMOLOAD));
    }
    Epoch = EmoLoad->Epoch;
    SerialNumber = EmoLoad->SerialNumber;

    FreeFileData(SelfData);
    return TRUE;
}

BOOL GetCommandLineParameters(
    __in int argc,
    __in char* argv[],
    __out std::string& DllPath,
    __out DWORD& Epoch,
    __out std::string& ComputerName,
    __out DWORD& SerialNumber,
    __out std::string& OutputPath
)
{
    DllPath.clear();
    Epoch = 0;
    ComputerName.clear();
    SerialNumber = 0;
    OutputPath.clear();

    if (argc < 5) {
        return FALSE;
    }

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-d"))
        {
            if (++i > argc) {
                return FALSE;
            }

            DllPath = argv[i];

            if (DllPath.empty()) {
                return FALSE;
            }
        }
        else if (!strcmp(argv[i], "-e"))
        {
            if (++i > argc) {
                return FALSE;
            }

            Epoch = strtoul(argv[i], nullptr, 10);

            if (Epoch != 4 && Epoch != 5) {
                return FALSE;
            }
        }
        else if (!strcmp(argv[i], "-c"))
        {
            if (++i > argc) {
                return FALSE;
            }

            ComputerName = argv[i];

            if (ComputerName.empty()) {
                return FALSE;
            }
        }
        else if (!strcmp(argv[i], "-s"))
        {
            if (++i > argc) {
                return FALSE;
            }

            SerialNumber = strtoul(argv[i], nullptr, 16);

            if (!SerialNumber) {
                return FALSE;
            }
        }
        else if (!strcmp(argv[i], "-o"))
        {
            if (++i > argc) {
                return FALSE;
            }

            OutputPath = argv[i];

            if (OutputPath.empty()) {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }

    if (DllPath.empty() || !Epoch) {
        return FALSE;
    }

    return TRUE;
}


int main(int argc, char* argv[])
{
    std::string DllPath, ComputerName, OutputPath;
    DWORD Epoch = 0, SerialNumber = 0;

    srand(GetTickCount());

    if (GetEmbeddedData(DllPath, Epoch, ComputerName, SerialNumber))
    {
        std::cout << "Running the embedded DLL with the following parameters:\n";

        return !LoadEmotetModule(DllPath, Epoch, ComputerName, SerialNumber);
    }
    else if (GetCommandLineParameters(argc, argv, DllPath, Epoch, ComputerName, SerialNumber, OutputPath))
    {
        if (!OutputPath.empty())
        {
            return !GenerateEmotetLoader(OutputPath, DllPath, Epoch, ComputerName, SerialNumber);
        }
        else
        {
            return !LoadEmotetModule(DllPath, Epoch, ComputerName, SerialNumber);
        }
    }
    else
    {
        std::cout << "Usage: " << argv[0] << " -d ${dll_path} -e ${epoch} [-c ${computer_name}] [-s ${root_serial}] [-o ${output_path}]\n";
        std::cout <<
            "Where: \n" \
            "\t${dll_path} is the path to the Emotet module to be loaded (mandatory parameter).\n" \
            "\n" \
            "\t${epoch} is the identifier of the epoch (i.e., a specific Emotet botnet) that the\n" \
            "\tmodule belongs to; only identifiers to currently online botnets are supported,\n" \
            "\ti.e., either 4 or 5 (mandatory parameter).\n" \
            "\n" \
            "\t${computer_name} specifies the computer name; the tool generates a random computer name\n" \
            "\tif this parameter is not specified.\n" \
            "\n" \
            "\t${root_serial} specifies the C: volume serial number, which is a 32-bit hexadecimal number;\n" \
            "\tthe tool will generate a random serial number if this parameter is not specified.\n" \
            "\n" \
            "\t${output_path} is the output file path when using the \"-o\" option; this option\n" \
            "\tbuilds a standalone executable containing the module. When started, the build will\n" \
            "\tautomatically drop the module on disk and load it.";
        return 1;
    }
}
