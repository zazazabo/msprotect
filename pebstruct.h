
typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;
    UCHAR CURDIR[0xc];
    UNICODE_STRING32 DllPath;
    UNICODE_STRING32 ImagePathName; //进程完整路径
    UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG64 ConsoleHandle;
    ULONG64 ConsoleFlags;
    ULONG64 StandardInput;
    ULONG64 StandardOutput;
    ULONG64 StandardError;
    UCHAR CURDIR[0x14];
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName; //进程完整路径
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _PEB32
{ // Size: 0x1D8
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR SpareBool;
    HANDLE Mutant;
    ULONG ImageBaseAddress;
    ULONG DllList;
    ULONG ProcessParameters; //进程参数块
} PEB32, *PPEB32;

typedef struct _PEB64
{ // Size: 0x1D8
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR SpareBool[5];
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64 DllList;
    ULONG64 ProcessParameters; //进程参数块
} PEB64, *PPEB64;

typedef PPEB(__stdcall *P_PsGetProcessWow64Process)(PEPROCESS);
P_PsGetProcessWow64Process PsGetProcessWow64Process = NULL;
typedef PPEB(__stdcall *P_PsGetProcessPeb)(PEPROCESS);
P_PsGetProcessPeb PsGetProcessPeb = NULL;
