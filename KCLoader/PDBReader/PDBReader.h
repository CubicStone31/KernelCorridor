#pragma once
#include <string>
#include <atlbase.h>
#include "./dia2.h"
#include <optional>

class PDBReader {
public:
    PDBReader(std::wstring pdb_name);

    PDBReader(std::wstring executable_name, std::wstring search_path);

    std::optional<size_t> FindSymbol(std::wstring sym, DWORD &type);

    std::optional<size_t> FindConst(std::wstring const_name);

    size_t FindFunction(std::wstring func);

    std::optional<LONG> FindStructMemberOffset(std::wstring structName, std::wstring memberName);

    // ~PDBReader();

    static HRESULT COINIT(DWORD init_flag);

    static void DownloadPDBForFile(std::wstring executable_name, std::wstring symbol_folder);

    static HRESULT CreateDiaDataSourceWithoutComRegistration(IDiaDataSource** data_source);

private:
    static inline std::wstring dia_dll_name = L"msdia140.dll";

    CComPtr<IDiaSession> pSession;

    CComPtr<IDiaSymbol> pGlobal;
};
