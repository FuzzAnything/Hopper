
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define INVALID_HANDLE_VALUE NULL
#define FILE_MAP_ALL_ACCESS (0x000F0000L|0x0001|0x0002|0x0004|0x0008|0x00100)
#define PAGE_EXECUTE_READWRITE  0x40  
typedef int WCHAR;     
typedef const WCHAR *LPCWSTR, *PCWSTR;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char BOOLEAN;
typedef int BOOL;
typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned char UCHAR;
typedef unsigned short *PWSTR;
typedef DWORD ACCESS_MASK;
typedef void *HANDLE;
typedef void *LPVOID;
typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG_PTR;
// typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;
// typedef unsigned __int64 ULONGLONG;
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

static e9_safe_call_t safe_call = NULL;

#ifdef DEBUG 
typedef int (*set_console_text_attribute_t)(intptr_t, int16_t);
typedef int (*write_file_t)(intptr_t, void *, size_t, void *, void *);
static intptr_t stderr = 0;
/*
 * Windows library functions.
 */
#define FOREGROUND_BLUE      0x1
#define FOREGROUND_GREEN     0x2
#define FOREGROUND_RED       0x4
#define FOREGROUND_YELLOW    (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_WHITE    \
    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
static set_console_text_attribute_t set_console_text_attribute_fn = NULL;
static write_file_t write_file_fn = NULL;

static int SetConsoleTextAttribute(intptr_t handle, int16_t attr)
{
    return (int)safe_call(set_console_text_attribute_fn, handle, attr);
}
static int WriteFile(intptr_t handle, void *buf, size_t len, void *x,
    void *y)
{
    return (int)safe_call(write_file_fn, handle, buf, len, x, y);
}

/*
 * Get the stderr handle (& do some init if required).
 */
static intptr_t get_stderr(const struct e9_config_s *config)
{
    const struct e9_config_pe_s *config_pe =
    (const struct e9_config_pe_s *)(config + 1);
    return config_pe->stderr_handle;
}

/*
 * fprintf(...) adatped from stdlib.c
 */
#define PRINTF_FLAG_NEG        0x0001
#define PRINTF_FLAG_UPPER      0x0002
#define PRINTF_FLAG_HEX        0x0004
#define PRINTF_FLAG_PLUS       0x0008
#define PRINTF_FLAG_HASH       0x0010
#define PRINTF_FLAG_SPACE      0x0020
#define PRINTF_FLAG_RIGHT      0x0040
#define PRINTF_FLAG_ZERO       0x0080
#define PRINTF_FLAG_PRECISION  0x0100
#define PRINTF_FLAG_8          0x0200
#define PRINTF_FLAG_16         0x0400
#define PRINTF_FLAG_64         0x0800
static int isdigit(int c)
{
        return (c >= '0' && c <= '9');
}
static size_t strlen(const char *s)
{
    size_t len = 0;
    while (*s++ != '\0')
        len++;
    return len;
}
static __attribute__((__noinline__)) size_t printf_put_char(char *str,
    size_t size, size_t idx, char c)
{
    if (str == NULL || idx >= size)
        return idx+1;
    str[idx++] = c;
    return idx;
}
static __attribute__((__noinline__)) size_t printf_put_num(char *str,
    size_t size, size_t idx, unsigned flags, size_t width, size_t precision,
    unsigned long long x)
{
    char prefix[2] = {'\0', '\0'};
    char buf[32];
    size_t i = 0;
    if (flags & PRINTF_FLAG_HEX)
    {
        if (flags & PRINTF_FLAG_HASH)
        {
            prefix[0] = '0';
            prefix[1] = (flags & PRINTF_FLAG_UPPER? 'X': 'x');
        }
        const char digs[] = "0123456789abcdef";
        const char DIGS[] = "0123456789ABCDEF";
        const char *ds = (flags & PRINTF_FLAG_UPPER? DIGS: digs);
        int shift = (15 * 4);
        bool seen = false;
        while (shift >= 0)
        {
            char c = ds[(x >> shift) & 0xF];
            shift -= 4;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    else
    {
        if (flags & PRINTF_FLAG_NEG)
            prefix[0] = '-';
        else if (flags & PRINTF_FLAG_PLUS)
            prefix[0] = '+';
        else if (flags & PRINTF_FLAG_SPACE)
            prefix[0] = ' ';
        unsigned long long r = 10000000000000000000ull;
        bool seen = false;
        while (r != 0)
        {
            char c = '0' + x / r;
            x %= r;
            r /= 10;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    if ((flags & PRINTF_FLAG_ZERO) && !(flags & PRINTF_FLAG_PRECISION))
    {
        precision = width;
        width = 0;
    }
    size_t len_0 = i;
    size_t len_1 = (len_0 < precision? precision: len_0);
    size_t len   =
        len_1 + (prefix[0] != '\0'? 1 + (prefix[1] != '\0'? 1: 0): 0);
    if (!(flags & PRINTF_FLAG_RIGHT))
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    if (prefix[0] != '\0')
    {
        idx = printf_put_char(str, size, idx, prefix[0]);
        if (prefix[1] != '\0')
            idx = printf_put_char(str, size, idx, prefix[1]);
    }
    for (size_t i = 0; precision > len_0 && i < precision - len_0; i++)
        idx = printf_put_char(str, size, idx, '0');
    for (size_t i = 0; i < len_0; i++)
        idx = printf_put_char(str, size, idx, buf[i]);
    if (flags & PRINTF_FLAG_RIGHT)
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    return idx;
}
static int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    size_t idx = 0;
    for (; *format != '\0'; format++)
    {
        if (*format != '%')
        {
            idx = printf_put_char(str, size, idx, *format);
            continue;
        }
        format++;
        unsigned flags = 0x0;
        for (; true; format++)
        {
            switch (*format)
            {
                case ' ':
                    flags |= PRINTF_FLAG_SPACE;
                    continue;
                case '+':
                    flags |= PRINTF_FLAG_PLUS;
                    continue;
                case '-':
                    if (!(flags & PRINTF_FLAG_ZERO))
                        flags |= PRINTF_FLAG_RIGHT;
                    continue;
                case '#':
                    flags |= PRINTF_FLAG_HASH;
                    continue;
                case '0':
                    flags &= ~PRINTF_FLAG_RIGHT;
                    flags |= PRINTF_FLAG_ZERO;
                    continue;
                default:
                    break;
            }
            break;
        }

        size_t width = 0;
        if (*format == '*')
        {
            format++;
            int tmp = va_arg(ap, int);
            if (tmp < 0)
            {
                flags |= (!(flags & PRINTF_FLAG_ZERO)? PRINTF_FLAG_RIGHT: 0);
                width = (size_t)-tmp;
            }
            else
                width = (size_t)tmp;
        }
        else
        {
            for (; isdigit(*format); format++)
            {
                width *= 10;
                width += (unsigned)(*format - '0');
                width = (width > INT32_MAX? INT32_MAX: width);
            }
        }
        width = (width > INT16_MAX? INT16_MAX: width);

        size_t precision = 0;
        if (*format == '.')
        {
            flags |= PRINTF_FLAG_PRECISION;
            format++;
            if (*format == '*')
            {
                format++;
                int tmp = va_arg(ap, int);
                tmp = (tmp < 0? 0: tmp);
                precision = (size_t)tmp;
            }
            else
            {
                for (; isdigit(*format); format++)
                {
                    precision *= 10;
                    precision += (unsigned)(*format - '0');
                    precision = (precision > INT32_MAX? INT32_MAX: precision);
                }
            }
        }
        switch (*format)
        {
            case 'l':
                flags |= PRINTF_FLAG_64;
                format++;
                if (*format == 'l')
                    format++;
                break;
            case 'h':
                format++;
                if (*format == 'h')
                {
                    format++;
                    flags |= PRINTF_FLAG_8;
                }
                else
                    flags |= PRINTF_FLAG_16;
                break;
            case 'z': case 'j': case 't':
                format++;
                flags |= PRINTF_FLAG_64;
                break;
        }

        int64_t x;
        uint64_t y;
        const char *s;
        size_t len;
        bool end = false;
        switch (*format)
        {
            case '\0':
                end = true;
                break;
            case 'c':
                x = (int64_t)(char)va_arg(ap, int);
                idx = printf_put_char(str, size, idx, (char)x);
                break;
            case 'd': case 'i':
                if (flags & PRINTF_FLAG_8)
                    x = (int64_t)(int8_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_16)
                    x = (int64_t)(int16_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_64)
                    x = va_arg(ap, int64_t);
                else
                    x = (int64_t)va_arg(ap, int);
                if (x < 0)
                {
                    flags |= PRINTF_FLAG_NEG;
                    x = -x;
                }
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, (uint64_t)x);
                break;
            case 'X':
                flags |= PRINTF_FLAG_UPPER;
                // Fallthrough
            case 'x':
                flags |= PRINTF_FLAG_HEX;
                // Fallthrough
            case 'u':
                if (flags & PRINTF_FLAG_8)
                    y = (uint64_t)(uint8_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_16)
                    y = (uint64_t)(uint16_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_64)
                    y = va_arg(ap, uint64_t);
                else
                    y = (uint64_t)va_arg(ap, unsigned);
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 'p':
                y = (uint64_t)va_arg(ap, const void *);
                flags |= PRINTF_FLAG_HASH | PRINTF_FLAG_HEX;
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 's':
                s = va_arg(ap, const char *);
                s = (s == NULL? "(null)": s);
                len = strlen(s);
                len = ((flags & PRINTF_FLAG_PRECISION) && precision < len?
                    precision: len);
                if (!(flags & PRINTF_FLAG_RIGHT))
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                for (size_t i = 0; i < len; i++)
                    idx = printf_put_char(str, size, idx, s[i]);
                if (flags & PRINTF_FLAG_RIGHT)
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                break;
            default:
                idx = printf_put_char(str, size, idx, *format);
                break;
        }
        if (end)
            break;
    }
    (void)printf_put_char(str, size, idx, '\0');
    if (idx > INT32_MAX)
        return -1;
    return (int)idx;
}
static int e9vfprintf(intptr_t handle, const char *format, va_list ap)
{
    va_list ap1; 
    va_copy(ap1, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result < 0)
        return result;
    char buf[result+1];
    result = vsnprintf(buf, result+1, format, ap1);
    if (result < 0)
        return result;
    if (!WriteFile(handle, buf, strlen(buf), NULL, NULL))
        return -1;
    return result;
}
static int e9fprintf(intptr_t handle, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = e9vfprintf(handle, format, ap);
    va_end(ap);
    return result;
}
#endif

typedef HANDLE (*create_file_mapping_t)(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCWSTR lpName);
static create_file_mapping_t create_file_mapping_fn = NULL; 

static HANDLE CreateFileMappingSC(HANDLE hFile,LPSECURITY_ATTRIBUTES lpFileMappingAttributes,DWORD flProtect,DWORD dwMaximumSizeHigh,DWORD dwMaximumSizeLow,LPCWSTR lpName){
    return (HANDLE)safe_call(create_file_mapping_fn, hFile, lpFileMappingAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,lpName);
}

typedef void* (*map_view_of_file_ex_t)(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap,LPVOID lpBaseAddress);
static map_view_of_file_ex_t map_view_of_file_ex_fn = NULL; 

static HANDLE MapViewOfFileExSC(HANDLE hFileMappingObject,DWORD dwDesiredAccess,DWORD dwFileOffsetHigh,DWORD dwFileOffsetLow,SIZE_T dwNumberOfBytesToMap,LPVOID lpBaseAddress){
    return (HANDLE)safe_call(map_view_of_file_ex_fn, hFileMappingObject, dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,dwNumberOfBytesToMap,lpBaseAddress);
}

typedef DWORD (*get_environment_variable_t)(char* lpName, char* lpBuffer, DWORD nSize);
static get_environment_variable_t get_environment_variable_fn = NULL; 

static DWORD GetEnvironmentVariable(char* lpName, char* lpBuffer, DWORD nSize){
    return (DWORD)safe_call(get_environment_variable_fn, lpName, lpBuffer, nSize);
}

HANDLE DoCreateFileMapping(DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,LPCWSTR lpName) {
	SECURITY_ATTRIBUTES sec;
	sec.nLength = sizeof(sec);
	sec.lpSecurityDescriptor = NULL;
	sec.bInheritHandle = true;
	LPSECURITY_ATTRIBUTES secptr = &sec;
	HANDLE hFileMappingObject = CreateFileMappingSC(INVALID_HANDLE_VALUE, secptr, PAGE_EXECUTE_READWRITE, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
#ifdef DEBUG
	if (hFileMappingObject == INVALID_HANDLE_VALUE) {
        //asm volatile ("ud2");
		e9fprintf(stderr, "CreateMemoryMapping failed\n");
		return NULL;
	}
	else {
        //asm volatile ("ud2");
		e9fprintf(stderr, "CreateMemoryMapping succeed, HANDLE ==> %p\n", hFileMappingObject);
		return hFileMappingObject;
	}
#endif
    return hFileMappingObject;
}

void* DoMapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap,LPVOID lpBaseAddress) {
	void* ret_lpBaseAddress = MapViewOfFileExSC(hFileMappingObject, FILE_MAP_ALL_ACCESS, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap,lpBaseAddress);
#ifdef DEBUG
	if (!ret_lpBaseAddress) {
        //asm volatile ("ud2");
		e9fprintf(stderr, "DoMapViewOfFileEx failed. lpBaseAddress ==> %p arg ==> %p\n", ret_lpBaseAddress,lpBaseAddress);
		return NULL;
	}
	else {
        //asm volatile ("ud2");
		e9fprintf(stderr, "DoMapViewOfFileEx succeed. lpBaseAddress ==> %p arg ==> %p\n", ret_lpBaseAddress,lpBaseAddress);
		return ret_lpBaseAddress;
	}
#endif
    return ret_lpBaseAddress;
}

void init(const struct e9_config_s *config)
{
    const struct e9_config_pe_s *config_pe =
        (const struct e9_config_pe_s *)(config + 1);
    if (safe_call == NULL)
        safe_call = config_pe->safe_call;
    if (create_file_mapping_fn == NULL)
        create_file_mapping_fn =
            (create_file_mapping_t)config_pe->get_proc_address(
                config_pe->kernel32, "CreateFileMappingA");
    if (map_view_of_file_ex_fn == NULL)
        map_view_of_file_ex_fn =
            (map_view_of_file_ex_t)config_pe->get_proc_address(
                config_pe->kernel32, "MapViewOfFileEx");     
    if (get_environment_variable_fn == NULL)
        get_environment_variable_fn =
            (get_environment_variable_t)config_pe->get_proc_address(
                config_pe->kernel32, "GetEnvironmentVariableA");  
#ifdef DEBUG
    if (set_console_text_attribute_fn == NULL)
        set_console_text_attribute_fn =
            (set_console_text_attribute_t)config_pe->get_proc_address(
                config_pe->kernel32, "SetConsoleTextAttribute");
    if (write_file_fn == NULL)
        write_file_fn =
            (write_file_t)config_pe->get_proc_address(
                config_pe->kernel32, "WriteFile");
    if (set_console_text_attribute_fn == NULL || write_file_fn == NULL)
        asm volatile ("ud2");
    stderr = get_stderr(config);
    SetConsoleTextAttribute(stderr, FOREGROUND_WHITE);
    e9fprintf(stderr, "set_console_text_attribute_fn: 0x%.16lx\n", set_console_text_attribute_fn);
    e9fprintf(stderr, "write_file_fn: 0x%.16lx\n", write_file_fn);
    e9fprintf(stderr, "create_file_mapping_fn: 0x%.16lx\n", create_file_mapping_fn);
    e9fprintf(stderr, "map_view_of_file_ex_fn: 0x%.16lx\n", map_view_of_file_ex_fn);
#endif
    // FIXME: crate a big enough mapping here, but the memoery we used is less than the size.
    size_t size = 0x100000;
    char path_val[0x40] = "HOPPER_PATH_SHMID_";
    GetEnvironmentVariable("HOPPER_TASK",path_val+18,0x40);
    HANDLE handle_area_base = DoCreateFileMapping((u_long) (size >> 32),(u_long) (size & 0xffffffff), (LPCWSTR)path_val);
    DoMapViewOfFileEx (handle_area_base, 0, 0, 0, (LPVOID)AREA_BASE);
    char instr_val[0x40] = "HOPPER_INSTR_SHMID_";
    GetEnvironmentVariable("HOPPER_TASK",instr_val+19,0x40);
    HANDLE handle_instr_area = DoCreateFileMapping((u_long) (size >> 32),(u_long) (size & 0xffffffff),(LPCWSTR)instr_val);
    DoMapViewOfFileEx(handle_instr_area, 0, 0, 0, (LPVOID)INSTR_AREA);
    *free_ptr = (int64_t)config_pe->get_proc_address(config_pe->user32, "free");   
    *malloc_ptr = (int64_t)config_pe->get_proc_address(config_pe->user32, "malloc");   
    *calloc_ptr = (int64_t)config_pe->get_proc_address(config_pe->user32, "calloc");   
    *realloc_ptr = (int64_t)config_pe->get_proc_address(config_pe->user32, "realloc");
#ifdef DEBUG
    e9fprintf(stderr, "path_val: %s\n", path_val);
    e9fprintf(stderr, "handle_area_base handle: 0x%.16lx\n", handle_area_base);
    e9fprintf(stderr, "instr_val: %s\n", instr_val);
    e9fprintf(stderr, "handle_instr_area handle: 0x%.16lx\n", handle_instr_area);
    e9fprintf(stderr, "free_ptr: 0x%.16lx\n", *free_ptr);
    e9fprintf(stderr, "malloc_ptr: 0x%.16lx\n", *malloc_ptr);
    e9fprintf(stderr, "calloc_ptr: 0x%.16lx\n", *calloc_ptr);
    e9fprintf(stderr, "realloc_ptr: 0x%.16lx\n", *realloc_ptr);
    e9fprintf(stderr, "===========================================================\n");
#endif
}