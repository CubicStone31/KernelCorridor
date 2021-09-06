// PDBReader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "PDBReader.h"
#include <filesystem>

PDBReader::PDBReader(std::wstring pdb_name) {
    CComPtr<IDiaDataSource> pSource;
    HRESULT hr;

    hr = CreateDiaDataSourceWithoutComRegistration(&pSource);
    if (FAILED(hr)) {
        throw std::exception("Could not CoCreate CLSID_DiaSource. You should place msdiaXX.dll in current folder.");
    }

    hr = pSource->loadDataFromPdb(pdb_name.c_str());
    if (FAILED(hr)) {
        throw std::exception("Could not load pdb file.");
    }

    hr = pSource->openSession(&this->pSession);
    if (FAILED(hr)) {
        throw std::exception("Could not open session.");
    }

    hr = pSession->get_globalScope(&this->pGlobal);
    if (FAILED(hr)) {
        throw std::exception("Could not get global scope.");
    }
}

PDBReader::PDBReader(std::wstring executable_name, std::wstring search_path) {
    CComPtr<IDiaDataSource> pSource;
    HRESULT hr;

    hr = CreateDiaDataSourceWithoutComRegistration(&pSource);
    if (FAILED(hr)) {
        throw std::exception("Could not CoCreate CLSID_DiaSource. You should place msdiaXX.dll in current folder.");
    }

    // using format: srv*search_path* to treat target folder as a symbol cache and search it recursively
    std::wstring search_str = std::filesystem::absolute(search_path);
    search_str = L"srv*" + search_str + L"*";
    hr = pSource->loadDataForExe(executable_name.c_str(), search_str.c_str(), 0);
    if (FAILED(hr)) {
        throw std::exception("Could not load pdb file.");
    }

    hr = pSource->openSession(&this->pSession);
    if (FAILED(hr)) {
        throw std::exception("Could not open session.");
    }

    hr = pSession->get_globalScope(&this->pGlobal);
    if (FAILED(hr)) {
        throw std::exception("Could not get global scope.");
    }
}

std::optional<size_t> PDBReader::FindSymbol(std::wstring sym, DWORD& type) {
    CComPtr<IDiaEnumSymbols> pEnumSymbols;
    HRESULT hr;
    type = SymTagEnum::SymTagNull;

    hr = this->pGlobal->findChildren(SymTagEnum::SymTagNull, sym.c_str(), nsfCaseSensitive, &pEnumSymbols);
    if (FAILED(hr)) {
        return {};
    }

    LONG count = 0;
    hr = pEnumSymbols->get_Count(&count);
    if (count != 1 || (FAILED(hr))) {
        return {};
    }

    CComPtr<IDiaSymbol> pSymbol;
    ULONG celt = 1;
    hr = pEnumSymbols->Next(1, &pSymbol, &celt);
    if ((FAILED(hr)) || (celt != 1)) {
        return {};
    }

    // get symbols's type info
    hr = pSymbol->get_symTag(&type);
    if (FAILED(hr)) {
        type = SymTagEnum::SymTagNull;
        return {};
    }

    ULONGLONG va = 0;
    hr = pSymbol->get_virtualAddress(&va);
    return va;
}

std::optional<size_t> PDBReader::FindConst(std::wstring const_name) {
    CComPtr<IDiaEnumSymbols> pEnumSymbols;
    HRESULT hr;

    hr = this->pGlobal->findChildren(SymTagEnum::SymTagData, const_name.c_str(), nsfCaseSensitive, &pEnumSymbols);
    if (FAILED(hr)) {
        return {};
    }

    LONG count = 0;
    hr = pEnumSymbols->get_Count(&count);
    if (count != 1 || (FAILED(hr))) {
        return {};
    }

    CComPtr<IDiaSymbol> pSymbol;
    ULONG celt = 1;
    hr = pEnumSymbols->Next(1, &pSymbol, &celt);
    if ((FAILED(hr)) || (celt != 1)) {
        return {};
    }

    ULONGLONG va = 0;
    hr = pSymbol->get_virtualAddress(&va);
    return va;
}

size_t PDBReader::FindFunction(std::wstring func) {
    CComPtr<IDiaEnumSymbols> pEnumSymbols;
    HRESULT hr;

    hr = this->pGlobal->findChildren(SymTagEnum::SymTagFunction, func.c_str(), nsfCaseSensitive, &pEnumSymbols);
    if (FAILED(hr)) {
        return 0;
    }

    LONG count = 0;
    hr = pEnumSymbols->get_Count(&count);
    if (count != 1 || (FAILED(hr))) {
        return 0;
    }

    CComPtr<IDiaSymbol> pSymbol;
    ULONG celt = 1;
    hr = pEnumSymbols->Next(1, &pSymbol, &celt);
    if ((FAILED(hr)) || (celt != 1)) {
        return 0;
    }

    ULONGLONG va = 0;
    hr = pSymbol->get_virtualAddress(&va);
    return va;
}

std::optional<LONG> PDBReader::FindStructMemberOffset(std::wstring structName, std::wstring memberName)
{
    CComPtr<IDiaEnumSymbols> pEnumSymbols;
    HRESULT hr;

    hr = this->pGlobal->findChildren(SymTagEnum::SymTagUDT, structName.c_str(), nsfCaseSensitive, &pEnumSymbols);
    if (FAILED(hr)) {
        return {};
    }

    LONG count = 0;
    hr = pEnumSymbols->get_Count(&count);
    if (count != 1 || (FAILED(hr))) {
        return {};
    }

    CComPtr<IDiaSymbol> pSymbol;
    ULONG celt = 1;
    hr = pEnumSymbols->Next(1, &pSymbol, &celt);
    if ((FAILED(hr)) || (celt != 1)) {
        return {};
    }

    CComPtr<IDiaEnumSymbols> structEnumSymbols;
    hr = pSymbol->findChildren(SymTagEnum::SymTagNull, memberName.c_str(), nsfCaseSensitive, &structEnumSymbols);
    if (FAILED(hr)) {
        return {};
    }

    count = 0;
    hr = structEnumSymbols->get_Count(&count);
    if (count != 1 || (FAILED(hr))) {
        return {};
    }

    CComPtr<IDiaSymbol> memberSymbol;
    celt = 1;
    hr = structEnumSymbols->Next(1, &memberSymbol, &celt);
    if ((FAILED(hr)) || (celt != 1)) {
        return {};
    }

    LONG offset = 0;
    hr = memberSymbol->get_offset(&offset);
    if (FAILED(hr)) {
        return {};
    }
    return offset;
}

HRESULT PDBReader::COINIT(DWORD init_flag) {
    return CoInitializeEx(0, init_flag);
}

void PDBReader::DownloadPDBForFile(std::wstring executable_name, std::wstring symbol_folder) {
    CComPtr<IDiaDataSource> pSource;
    HRESULT hr;

    hr = CreateDiaDataSourceWithoutComRegistration(&pSource);
    if (FAILED(hr)) {
        throw std::exception("Could not CoCreate CLSID_DiaSource. You should place msdiaXX.dll in current folder.");
    }

    std::filesystem::path sym_cache_folder = std::filesystem::absolute(symbol_folder);
    std::wstring MS_SYMBOL_SERVER = L"https://msdl.microsoft.com/download/symbols";
    std::wstring seach_path = std::wstring(L"srv*") + sym_cache_folder.c_str() + L"*" + MS_SYMBOL_SERVER;

    hr = pSource->loadDataForExe(executable_name.c_str(), seach_path.c_str(), 0);
    if (FAILED(hr)) {
        throw std::exception("Failed to download symbols. Maybe you should place symsrv.dll in current folder or check your internet connection.");
    }

    return;
}

// We dont want to regsvr32 msdia140.dll on client's machine...
HRESULT PDBReader::CreateDiaDataSourceWithoutComRegistration(IDiaDataSource** data_source) {
    HMODULE hmodule = LoadLibraryW(PDBReader::dia_dll_name.c_str());

    // try to load dia dll in the same folder as main executable's
    if (!hmodule) {
        wchar_t temp[MAX_PATH] = { 0 };
        GetModuleFileNameW(0, temp, MAX_PATH);
        std::filesystem::path dllPath(temp);
        dllPath = dllPath.parent_path() / L"msdia140.dll";

        hmodule = LoadLibraryW(dllPath.c_str());
        if (!hmodule)
            return HRESULT_FROM_WIN32(GetLastError()); // library not found
    }

    BOOL(WINAPI * DllGetClassObject)(REFCLSID, REFIID, LPVOID*) =
        (BOOL(WINAPI*)(REFCLSID, REFIID, LPVOID*))GetProcAddress(hmodule, "DllGetClassObject");
    if (!DllGetClassObject)
        return E_FAIL;

    IClassFactory* pClassFactory;
    HRESULT hr = DllGetClassObject(CLSID_DiaSource, IID_IClassFactory, (LPVOID *)&pClassFactory);
    if (FAILED(hr))
        return hr;

    hr = pClassFactory->CreateInstance(NULL, IID_IDiaDataSource, (void **)data_source);
    if (FAILED(hr)) {
        pClassFactory->Release();
        return hr;
    }
        
    pClassFactory->Release();
    return S_OK;
}