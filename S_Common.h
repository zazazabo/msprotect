#ifndef _COMMON_H_
#define _COMMON_H_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define SECPROC_MAXCOUNT    8


//
//
////
////  Stream context data structure
////
//typedef struct _STREAM_CONTEXT {
//    //文件所在卷的扇区大小
//    USHORT SectorSize;
//	ULONG uAccess ;
//  LONG RefCount;
//
//	WCHAR wszVolumeName[64] ;
//  
//	 UNICODE_STRING FileName;
//    //加密算法索引号
//    USHORT CryptIndex;
//    //是否被机密进程打开
//    BOOLEAN bOpenBySecProc;
//    //上次写是否机密进程
//    BOOLEAN bWriteBySecProc;
//    //打开这个文件的机密进程ID，最多可以8个机密进程同时打开此文件
//    HANDLE uOpenSecProcID[SECPROC_MAXCOUNT];
//	
//	//Flags
//    BOOLEAN bIsFileCrypt ;    //(init false)set after file flag is written into end of file
//	
//    //Lock used to protect this context.
//    PERESOURCE Resource;
//	
//    //Spin lock used to protect this context when irql is too high
//    KSPIN_LOCK Spinlock ;
//	
//	LARGE_INTEGER AllocationSize;
//	LARGE_INTEGER OffsetLength;
//	LARGE_INTEGER FileSize;
//	LARGE_INTEGER ValidDataLength;
//
//	CF_WRITE_CONTEXT my_context;
//	
//} STREAM_CONTEXT, *PSTREAM_CONTEXT;



typedef struct _STREAM_CONTEXT {

    //Name of the file associated with this context.
    UNICODE_STRING FileName;

	//Volume Name
	WCHAR wszVolumeName[64] ;

	//desired access
	ULONG uAccess ;
	ULONG  uEncrypteType;   //加密类型     1 全部加密      2 除去某个进程，所有加密   
			
    //Number of times we saw a create on this stream
	//used to verify whether a file flag can be written
	//into end of file and file data can be flush back.
    LONG RefCount;

	//File Size(including real file size, padding length, and file flag data)
	LARGE_INTEGER FileSize ;

	//Lock used to protect this context.
       PERESOURCE Resource;

	//Spin lock used to protect this context when irql is too high
	KSPIN_LOCK Spinlock ;

} STREAM_CONTEXT, *PSTREAM_CONTEXT;
#define STREAM_CONTEXT_SIZE sizeof(STREAM_CONTEXT)




#endif
