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
//    //�ļ����ھ��������С
//    USHORT SectorSize;
//	ULONG uAccess ;
//  LONG RefCount;
//
//	WCHAR wszVolumeName[64] ;
//  
//	 UNICODE_STRING FileName;
//    //�����㷨������
//    USHORT CryptIndex;
//    //�Ƿ񱻻��ܽ��̴�
//    BOOLEAN bOpenBySecProc;
//    //�ϴ�д�Ƿ���ܽ���
//    BOOLEAN bWriteBySecProc;
//    //������ļ��Ļ��ܽ���ID��������8�����ܽ���ͬʱ�򿪴��ļ�
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
	ULONG  uEncrypteType;   //��������     1 ȫ������      2 ��ȥĳ�����̣����м���   
			
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
