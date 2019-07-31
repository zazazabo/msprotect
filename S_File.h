#ifndef _FILENAME_H_
#define _FILENMAE_H_

#include "S_Common.h"

#define CF_FILE_HEADER_SIZE (1024*4)


/**
 * Query file information
 */

NTSTATUS
cfFileGetStandInfo(
	PDEVICE_OBJECT dev,
	PFILE_OBJECT file,
	PLARGE_INTEGER allocate_size,
	PLARGE_INTEGER file_size,
	BOOLEAN *dir);

/**
 * Get file information
 */
NTSTATUS
cfFileGetStandInfo(
				   PDEVICE_OBJECT dev,
				   PFILE_OBJECT file,
				   PLARGE_INTEGER allocate_size,
				   PLARGE_INTEGER file_size,
				   BOOLEAN *dir);
				   



NTSTATUS 
cfFileReadWrite( 
				DEVICE_OBJECT *dev, 
				FILE_OBJECT *file,
				LARGE_INTEGER *offset,
				ULONG *length,
				void *buffer,
				BOOLEAN read_write);

// ×Ô·¢ËÍSetInformationÇëÇó.
NTSTATUS 
cfFileSetInformation( 
					 DEVICE_OBJECT *dev, 
					 FILE_OBJECT *file,
					 FILE_INFORMATION_CLASS infor_class,
					 FILE_OBJECT *set_file,
					 void* buf,
					 ULONG buf_len);

NTSTATUS
cfFileSetFileSize(
				  DEVICE_OBJECT *dev,
				  FILE_OBJECT *file,
				  LARGE_INTEGER *file_size);
NTSTATUS cfWriteAHeader(PFILE_OBJECT file,PDEVICE_OBJECT next_dev);


void cfFileCacheClear(PFILE_OBJECT pFileObject);

PMDL cfMdlMemoryAlloc(ULONG length);

void cfMdlMemoryFree(PMDL mdl);



NTSTATUS
GetFileOffset(
			  __in  PFLT_CALLBACK_DATA Data,
			  __in  PFLT_RELATED_OBJECTS FltObjects,
			  __out PLARGE_INTEGER FileOffset
				   );

NTSTATUS 
SetFileOffset(
			  __in  PFLT_CALLBACK_DATA Data,
			  __in  PFLT_RELATED_OBJECTS FltObjects,
			  __in PLARGE_INTEGER FileOffset
					);

GetFileStandardInfo(
					__in  PFLT_CALLBACK_DATA Data,
					__in  PFLT_RELATED_OBJECTS FltObjects,
					__in PLARGE_INTEGER FileAllocationSize,
					__in PLARGE_INTEGER FileSize,
					__in PBOOLEAN bDirectory
						 );

						 void Cc_ClearFileCache(PFILE_OBJECT FileObject, BOOLEAN bIsFlushCache, PLARGE_INTEGER FileOffset, ULONG Length);

#endif
