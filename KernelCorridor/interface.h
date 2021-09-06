#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define CC_READ_PROCESS_MEM ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_WRITE_PROCESS_MEM ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_CREATE_USER_THREAD ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_SET_HANDLE_PRIVILEGE ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_SET_PROCESS_PROTECTION_FIELD ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_INIT_UNDOCUMENTED_DATA ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_SET_HADNLE_ACCESS ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_DELETE_FILE ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_BSOD ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_DATA))
#define CC_SET_DSE ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_DATA))


//todo:
// https://www.unknowncheats.me/forum/anti-cheat-bypass/285491-pspnotifyenablemask-tricks-explained.html
#define CC_SET_NOTIFY_MASK ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_READ_DATA))
// https://github.com/dx9hk/MmUnloadedDrivers
// PiDDBCacheTable MmUnloadedDrivers
#define CC_CLEAR_DRIVER_TRACE ((ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_READ_DATA))


#define KC_DEVICE_NAME L"\\Device\\KernelCorridor"
#define KC_SYMBOLIC_NAME L"\\??\\KernelCorridor"

#pragma pack(push)
#pragma pack(8)

namespace KCProtocols
{
    enum class MEM_ACCESS_METHOD
    {
        MmCopyVirtualMemory,
        MapToKernelByMdl,
    };

    struct REQUEST_READ_PROCESS_MEM
    {
        MEM_ACCESS_METHOD method;
        UINT32 pid;
        SIZE_T size;
        PVOID addr;
    };

    struct RESPONSE_READ_PROCESS_MEM
    {
        SIZE_T size;
        UINT8 data[0];
    };

    struct REQUEST_WRITE_PROCESS_MEM
    {
        MEM_ACCESS_METHOD method;
        UINT32 pid;
        UINT32 size;
        PVOID addr;
        UINT8 data[0];
    };

    struct RESPONSE_WRITE_PROCESS_MEM
    {
        UINT32 bytesWritten;
    };

    struct REQUEST_CREATE_USER_THREAD
    {
        UINT32 pid;
        PVOID startAddr;
        PVOID parameter;
        bool createSuspended;
    };

    struct RESPONSE_CREATE_USER_THREAD
    {
        UINT32 processID;
        UINT32 threadID;
    };

    struct REQUEST_SET_PROCESS_PROTECTION_FIELD
    {
        UINT32 pid;
        bool queryOnly;
        UINT8 newProtect;
    };

    struct RESPONSE_SET_PROCESS_PROTECTION_FIELD
    {
        UINT8 oldProtect;
    };

    enum class UNDOCUMENTED_DATA_TYPE
    {
        EPROCESS_ImageFileName_Offset,
        EPROCESS_Protection_Offset,
        EPROCESS_ObjectTable_Offset,
        DriverSignatureEnforcement_Offset,
    };

    // NO RESPONSE FOR THIS REQUEST
    struct REQUEST_INIT_UNDOCUMENTED_DATA
    {
        UNDOCUMENTED_DATA_TYPE type;
        PVOID data;
    };

    struct REQUEST_SET_HANDLE_ACCESS
    {
        UINT32 pid;
        HANDLE handle;
        UINT32 newAccess;
        bool queryOnly;
    };

    struct RESPONSE_SET_HANDLE_ACCESS
    {
        UINT32 oldAccess;
    };

    // NO RESPONSE FOR THIS REQUEST
    struct REQUEST_DELETE_FILE
    {
        wchar_t path[256];
    };

    // NO REQUEST DATA AND RESPONSE FOR CONTROL CODE CC_BSOD

    struct REQUEST_SET_DSE
    {
        DWORD value;
        bool queryOnly;
    };

    struct RESPONSE_SET_DSE
    {
        DWORD oldValue;
    };
}

#pragma pack(pop)

static_assert(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) == 8, "Testing zero size array failed.");