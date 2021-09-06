#pragma once
#include <ntifs.h>

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
    // 15
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

#ifdef __cplusplus
extern "C" {
#endif
    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            PVOID SectionPointer;
        };
        ULONG CheckSum;
        union
        {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG          Length;
        BOOLEAN        Initialized;
        HANDLE         SsHandle;
        LIST_ENTRY     LoadOrder;
        LIST_ENTRY     MemoryOrder;
        LIST_ENTRY     InitializationOrder;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    typedef unsigned char* PBYTE;

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemModuleInformation = 11,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemRegistryQuotaInformation = 37,
        SystemLookasideInformation = 45,
        SystemCodeIntegrityInformation = 103,
        SystemPolicyInformation = 134,
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;      //下一个结构的偏移量，最后一个偏移量为0
        ULONG NumberOfThreads;
        LARGE_INTEGER SpareLi1;
        LARGE_INTEGER SpareLi2;
        LARGE_INTEGER SpareLi3;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;     //进程名
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;               //进程ID
        HANDLE InheritedFromUniqueProcessId;   //父进程ID
        ULONG HandleCount;
        ULONG SessionId;       //会话ID                    
        ULONG_PTR PageDirectoryBase;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

    typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
        UINT16   e_magic;                     // Magic number
        UINT16   e_cblp;                      // Bytes on last page of file
        UINT16   e_cp;                        // Pages in file
        UINT16   e_crlc;                      // Relocations
        UINT16   e_cparhdr;                   // Size of header in paragraphs
        UINT16   e_minalloc;                  // Minimum extra paragraphs needed
        UINT16   e_maxalloc;                  // Maximum extra paragraphs needed
        UINT16   e_ss;                        // Initial (relative) SS value
        UINT16   e_sp;                        // Initial SP value
        UINT16   e_csum;                      // Checksum
        UINT16   e_ip;                        // Initial IP value
        UINT16   e_cs;                        // Initial (relative) CS value
        UINT16   e_lfarlc;                    // File address of relocation table
        UINT16   e_ovno;                      // Overlay number
        UINT16   e_res[4];                    // Reserved words
        UINT16   e_oemid;                     // OEM identifier (for e_oeminfo)
        UINT16   e_oeminfo;                   // OEM information; e_oemid specific
        UINT16   e_res2[10];                  // Reserved words
        UINT32   e_lfanew;                    // File address of new exe header
    } IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_DATA_DIRECTORY {
        UINT32   VirtualAddress;
        UINT32   Size;
    } IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_FILE_HEADER {
        UINT16    Machine;
        UINT16    NumberOfSections;
        UINT32   TimeDateStamp;
        UINT32   PointerToSymbolTable;
        UINT32   NumberOfSymbols;
        UINT16    SizeOfOptionalHeader;
        UINT16    Characteristics;
    } IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        UINT16        Magic;
        UINT8        MajorLinkerVersion;
        UINT8        MinorLinkerVersion;
        UINT32       SizeOfCode;
        UINT32       SizeOfInitializedData;
        UINT32       SizeOfUninitializedData;
        UINT32       AddressOfEntryPoint;
        UINT32       BaseOfCode;
        ULONGLONG   ImageBase;
        UINT32       SectionAlignment;
        UINT32       FileAlignment;
        UINT16        MajorOperatingSystemVersion;
        UINT16        MinorOperatingSystemVersion;
        UINT16        MajorImageVersion;
        UINT16        MinorImageVersion;
        UINT16        MajorSubsystemVersion;
        UINT16        MinorSubsystemVersion;
        UINT32       Win32VersionValue;
        UINT32       SizeOfImage;
        UINT32       SizeOfHeaders;
        UINT32       CheckSum;
        UINT16        Subsystem;
        UINT16        DllCharacteristics;
        ULONGLONG   SizeOfStackReserve;
        ULONGLONG   SizeOfStackCommit;
        ULONGLONG   SizeOfHeapReserve;
        ULONGLONG   SizeOfHeapCommit;
        UINT32       LoaderFlags;
        UINT32       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

    typedef struct _IMAGE_NT_HEADERS64 {
        UINT32 Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

    typedef struct _IMAGE_EXPORT_DIRECTORY {
        UINT32   Characteristics;
        UINT32   TimeDateStamp;
        UINT16    MajorVersion;
        UINT16    MinorVersion;
        UINT32   Name;
        UINT32   Base;
        UINT32   NumberOfFunctions;
        UINT32   NumberOfNames;
        UINT32   AddressOfFunctions;     // RVA from base of image
        UINT32   AddressOfNames;         // RVA from base of image
        UINT32   AddressOfNameOrdinals;  // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

    typedef enum _WINDOWINFOCLASS {
        WindowProcess = 0,	// HANDLE
        WindowRealWindowOwner = 1,
        WindowThread = 2,	// HANDLE
        WindowIsHung = 5		// BOOL
    } WINDOWINFOCLASS;

    typedef struct _HANDLE_TABLE
    {
        ULONG NextHandleNeedingPool;
        long ExtraInfoPages;
        LONG_PTR TableCode;
        PEPROCESS QuotaProcess;
        LIST_ENTRY HandleTableList;
        ULONG UniqueProcessId;
        ULONG Flags;
        EX_PUSH_LOCK HandleContentionEvent;
        EX_PUSH_LOCK HandleTableLock;
        // More fields here...
    } HANDLE_TABLE, * PHANDLE_TABLE;

    typedef union _EXHANDLE
    {
        struct
        {
            int TagBits : 2;
            int Index : 30;
        } u;
        void* GenericHandleOverlay;
        ULONG_PTR Value;
    } EXHANDLE, * PEXHANDLE;

    typedef struct _HANDLE_TABLE_ENTRY // Size=16
    {
        union
        {
            ULONG_PTR VolatileLowValue; // Size=8 Offset=0
            ULONG_PTR LowValue; // Size=8 Offset=0
            struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
            struct
            {
                ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
                ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
                ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
                ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
            };
        };
        union
        {
            ULONG_PTR HighValue; // Size=8 Offset=8
            struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
            union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
            struct
            {
                ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
                ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
                ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
            };
        };
        ULONG TypeInfo; // Size=4 Offset=12
    } HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

#ifdef __cplusplus
}
#endif // _CPP