/****************************************************************************/
/*                             User include                                 */
/****************************************************************************/
#include <ntifs.h>

#include "S_File.h"


#define CF_MEM_TAG 'cffi'

static NTSTATUS cfFileIrpComp(
							  PDEVICE_OBJECT dev,
							  PIRP irp,
							  PVOID context
							  )
{
    *irp->UserIosb = irp->IoStatus;
    KeSetEvent(irp->UserEvent, 0, FALSE);
    IoFreeIrp(irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}



NTSTATUS
cfFileQueryInformation(
					   DEVICE_OBJECT *dev, 
					   FILE_OBJECT *file,
					   FILE_INFORMATION_CLASS infor_class,
					   void* buf,
					   ULONG buf_len)
{
    PIRP irp;
    KEVENT event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION ioStackLocation;
	
    // ��Ϊ���Ǵ������������ͬ����ɣ����Գ�ʼ��һ���¼�
    // �����ȴ�������ɡ�
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	
	// ����irp
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
	
	// ��дirp������
    irp->AssociatedIrp.SystemBuffer = buf;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
    irp->Flags = 0;
	
	// ����irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
    ioStackLocation->Parameters.QueryFile.Length = buf_len;
    ioStackLocation->Parameters.QueryFile.FileInformationClass = infor_class;
	
	// ���ý�������
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);
	
	// �������󲢵ȴ�����
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
    return IoStatusBlock.Status;
}


NTSTATUS
cfFileGetStandInfo(
				   PDEVICE_OBJECT dev,
				   PFILE_OBJECT file,
				   PLARGE_INTEGER allocate_size,
				   PLARGE_INTEGER file_size,
				   BOOLEAN *dir)
{
	NTSTATUS status;
	PFILE_STANDARD_INFORMATION infor = NULL;
	infor = (PFILE_STANDARD_INFORMATION)
		ExAllocatePoolWithTag(NonPagedPool,sizeof(FILE_STANDARD_INFORMATION),CF_MEM_TAG);
	if(infor == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	status = cfFileQueryInformation(dev,file,
		FileStandardInformation,(void *)infor,
		sizeof(FILE_STANDARD_INFORMATION));
	if(NT_SUCCESS(status))
	{
		if(allocate_size != NULL)
			*allocate_size = infor->AllocationSize;
		if(file_size != NULL)
			*file_size = infor->EndOfFile;
		if(dir != NULL)
			*dir = infor->Directory;
	}
	ExFreePool(infor);
	return status;
}

NTSTATUS
GetFileStandardInfo(
						 __in  PFLT_CALLBACK_DATA Data,
						 __in  PFLT_RELATED_OBJECTS FltObjects,
						 __in PLARGE_INTEGER FileAllocationSize,
						 __in PLARGE_INTEGER FileSize,
						 __in PBOOLEAN bDirectory
						 )
{
	NTSTATUS status = STATUS_SUCCESS ;
	FILE_STANDARD_INFORMATION sFileStandardInfo ;
	
	//�޸�Ϊ���²�Call
	status = FltQueryInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&sFileStandardInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation,
		NULL
		) ;
	if (NT_SUCCESS(status))
	{
		if (NULL != FileSize)
			*FileSize = sFileStandardInfo.EndOfFile ;
		if (NULL != FileAllocationSize)
			*FileAllocationSize = sFileStandardInfo.AllocationSize ;
		if (NULL != bDirectory)
			*bDirectory = sFileStandardInfo.Directory ;
	}
	
	return status ;
}

NTSTATUS cfFileReadWrite( 
			DEVICE_OBJECT *dev, 
			FILE_OBJECT *file,
			LARGE_INTEGER *offset,
			ULONG *length,
			void *buffer,
			BOOLEAN read_write) 
{
	ULONG i;
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	
	// ����irp.
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
	
	// ��д���塣
    irp->AssociatedIrp.SystemBuffer = NULL;
	// ��paging io������£��ƺ�����Ҫʹ��MDL�����������С�����ʹ��UserBuffer.
	// �����Ҳ����϶���һ�㡣���������һ�����ԡ��Ա��ҿ��Ը��ٴ���
    irp->MdlAddress = NULL;
    irp->UserBuffer = buffer;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
	if(read_write)
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_READ_OPERATION|IRP_NOCACHE;
	else
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_WRITE_OPERATION|IRP_NOCACHE;
	
	// ��дirpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
	if(read_write)
		ioStackLocation->MajorFunction = IRP_MJ_READ;
	else
		ioStackLocation->MajorFunction = IRP_MJ_WRITE;
    ioStackLocation->MinorFunction = IRP_MN_NORMAL;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
	if(read_write)
	{
		ioStackLocation->Parameters.Read.ByteOffset = *offset;
		ioStackLocation->Parameters.Read.Length = *length;
	}
	else
	{
		ioStackLocation->Parameters.Write.ByteOffset = *offset;
		ioStackLocation->Parameters.Write.Length = *length;
	}
	
	// �������
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
	*length = IoStatusBlock.Information;
    return IoStatusBlock.Status;
}


// �Է���SetInformation����.
NTSTATUS 
cfFileSetInformation( 
					 DEVICE_OBJECT *dev, 
					 FILE_OBJECT *file,
					 FILE_INFORMATION_CLASS infor_class,
					 FILE_OBJECT *set_file,
					 void* buf,
					 ULONG buf_len)
{
    PIRP irp;
    KEVENT event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION ioStackLocation;
	
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	
	// ����irp
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
	
	// ��дirp������
    irp->AssociatedIrp.SystemBuffer = buf;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
    irp->Flags = 0;
	
	// ����irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_SET_INFORMATION;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
    ioStackLocation->Parameters.SetFile.FileObject = set_file;
    ioStackLocation->Parameters.SetFile.Length = buf_len;
    ioStackLocation->Parameters.SetFile.FileInformationClass = infor_class;
	
	// ���ý�������
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);
	
	// �������󲢵ȴ�����
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
    return IoStatusBlock.Status;
}


NTSTATUS
cfFileSetFileSize(
				  DEVICE_OBJECT *dev,
				  FILE_OBJECT *file,
				  LARGE_INTEGER *file_size)
{
	FILE_END_OF_FILE_INFORMATION end_of_file;
	end_of_file.EndOfFile.QuadPart = file_size->QuadPart;
	return cfFileSetInformation(
		dev,file,FileEndOfFileInformation,
		NULL,(void *)&end_of_file,
		sizeof(FILE_END_OF_FILE_INFORMATION));
}


// д��һ���ļ�ͷ��
NTSTATUS cfWriteAHeader(PFILE_OBJECT file,PDEVICE_OBJECT next_dev)
{
    static WCHAR header_flags[CF_FILE_HEADER_SIZE/sizeof(WCHAR)] = {L'C',L'F',L'H',L'D'};
    LARGE_INTEGER file_size,offset;
    ULONG length = CF_FILE_HEADER_SIZE;
    NTSTATUS status;
	
    offset.QuadPart = 0;
    file_size.QuadPart = CF_FILE_HEADER_SIZE;
    // ���������ļ��Ĵ�СΪ4k��
    status = cfFileSetFileSize(next_dev,file,&file_size);
    if(status != STATUS_SUCCESS)
        return status;
	
    // Ȼ��д��8���ֽڵ�ͷ��
	return cfFileReadWrite(next_dev,file,&offset,&length,header_flags,FALSE);
}


// ������
void cfFileCacheClear(PFILE_OBJECT pFileObject)
{
   PFSRTL_COMMON_FCB_HEADER pFcb;
   LARGE_INTEGER liInterval;
   BOOLEAN bNeedReleaseResource = FALSE;
   BOOLEAN bNeedReleasePagingIoResource = FALSE;
   KIRQL irql;

   pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
   if(pFcb == NULL)
       return;

   irql = KeGetCurrentIrql();
   if (irql >= DISPATCH_LEVEL)
   {
       return;
   }

   liInterval.QuadPart = -1 * (LONGLONG)50;

   while (TRUE)
   {
       BOOLEAN bBreak = TRUE;
       BOOLEAN bLockedResource = FALSE;
       BOOLEAN bLockedPagingIoResource = FALSE;
       bNeedReleaseResource = FALSE;
       bNeedReleasePagingIoResource = FALSE;

	   // ��fcb��ȥ������
       if (pFcb->PagingIoResource)
           bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

	   // ��֮һ��Ҫ�õ��������
       if (pFcb->Resource)
       {
           bLockedResource = TRUE;
           if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
           {
               bNeedReleaseResource = TRUE;
               if (bLockedPagingIoResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bNeedReleaseResource = FALSE;
                       bLockedResource = FALSE;
                   }
               }
               else
                   ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
           }
       }
   
       if (bLockedPagingIoResource == FALSE)
       {
           if (pFcb->PagingIoResource)
           {
               bLockedPagingIoResource = TRUE;
               bNeedReleasePagingIoResource = TRUE;
               if (bLockedResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bLockedPagingIoResource = FALSE;
                       bNeedReleasePagingIoResource = FALSE;
                   }
               }
               else
               {
                   ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
               }
           }
       }

       if (bBreak)
       {
           break;
       }
       
       if (bNeedReleasePagingIoResource)
       {
           ExReleaseResourceLite(pFcb->PagingIoResource);
       }
       if (bNeedReleaseResource)
       {
           ExReleaseResourceLite(pFcb->Resource);
       }

       if (irql == PASSIVE_LEVEL)
       {
           KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
       }
       else
       {
           KEVENT waitEvent;
           KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
           KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
       }
   }

   if (pFileObject->SectionObjectPointer)
   {
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(pFileObject->SectionObjectPointer,MmFlushForWrite); // MmFlushForDelete
		}
		CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
   }

   if (bNeedReleasePagingIoResource)
   {
       ExReleaseResourceLite(pFcb->PagingIoResource);
   }
   if (bNeedReleaseResource)
   {
       ExReleaseResourceLite(pFcb->Resource);
   }
}

// ����һ��MDL������һ������Ϊlength�Ļ�������
PMDL cfMdlMemoryAlloc(ULONG length)
{
    void *buf = ExAllocatePoolWithTag(NonPagedPool,length,CF_MEM_TAG);
    PMDL mdl;
    if(buf == NULL)
        return NULL;
    mdl = IoAllocateMdl(buf,length,FALSE,FALSE,NULL);
    if(mdl == NULL)
    {
        ExFreePool(buf);
        return NULL;
    }
    MmBuildMdlForNonPagedPool(mdl);
    mdl->Next = NULL;
    return mdl;
}

// �ͷŵ�����MDL�Ļ�������
void cfMdlMemoryFree(PMDL mdl)
{
    void *buffer = MmGetSystemAddressForMdlSafe(mdl,NormalPagePriority);
    IoFreeMdl(mdl);
    ExFreePool(buffer);
}



NTSTATUS
GetFileOffset(
				   __in  PFLT_CALLBACK_DATA Data,
				   __in  PFLT_RELATED_OBJECTS FltObjects,
				   __out PLARGE_INTEGER FileOffset
				   )
{
	NTSTATUS status;
	FILE_POSITION_INFORMATION NewPos;
	
	//�޸�Ϊ���²�Call
	status = FltQueryInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&NewPos,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation,
		NULL
		) ;
	if (NT_SUCCESS(status))
	{
		FileOffset->QuadPart = NewPos.CurrentByteOffset.QuadPart;
	}
	
	return status;
}



NTSTATUS SetFileOffset(
							__in  PFLT_CALLBACK_DATA Data,
							__in  PFLT_RELATED_OBJECTS FltObjects,
							__in PLARGE_INTEGER FileOffset
							)
{
	NTSTATUS status;
	FILE_POSITION_INFORMATION NewPos;
	//�޸�Ϊ���²�Call
	LARGE_INTEGER NewOffset = {0};
	
	NewOffset.QuadPart = FileOffset->QuadPart;
	NewOffset.LowPart = FileOffset->LowPart;
	
	NewPos.CurrentByteOffset = NewOffset;
	
	status = FltSetInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&NewPos,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation
		) ;
	return status;
}




void Cc_ClearFileCache(PFILE_OBJECT FileObject, BOOLEAN bIsFlushCache, PLARGE_INTEGER FileOffset, ULONG Length)
{
	BOOLEAN PurgeRes ;
	BOOLEAN ResourceAcquired = FALSE ;
	BOOLEAN PagingIoResourceAcquired = FALSE ;
	PFSRTL_COMMON_FCB_HEADER Fcb = NULL ;
	LARGE_INTEGER Delay50Milliseconds = {(ULONG)(-50 * 1000 * 10), -1};
	IO_STATUS_BLOCK IoStatus = {0} ;

	if ((FileObject == NULL))
	{
		return ;
	}

	   Fcb = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext ;
	if (Fcb == NULL)
	{
		return ;
	}
	
Acquire:
	FsRtlEnterFileSystem() ;

	if (Fcb->Resource)
		ResourceAcquired = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE) ;
	if (Fcb->PagingIoResource)
		PagingIoResourceAcquired = ExAcquireResourceExclusive(Fcb->PagingIoResource,FALSE);
	else
		PagingIoResourceAcquired = TRUE ;
	if (!PagingIoResourceAcquired)
	{
		if (Fcb->Resource)	ExReleaseResource(Fcb->Resource);
		FsRtlExitFileSystem();
		KeDelayExecutionThread(KernelMode,FALSE,&Delay50Milliseconds);	
		goto Acquire;	
	}

	if(FileObject->SectionObjectPointer)
	{
		IoSetTopLevelIrp( (PIRP)FSRTL_FSP_TOP_LEVEL_IRP );

		if (bIsFlushCache)
		{
			CcFlushCache( FileObject->SectionObjectPointer, FileOffset, Length, &IoStatus );
		}

		if(FileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(
				FileObject->SectionObjectPointer,
				MmFlushForWrite
				) ;
		}

		if(FileObject->SectionObjectPointer->DataSectionObject)
		{ 
			PurgeRes = CcPurgeCacheSection( FileObject->SectionObjectPointer,
				NULL,
				0,
				FALSE );													
		}  
									  
		IoSetTopLevelIrp(NULL); 								  
	}

	if (Fcb->PagingIoResource)
		ExReleaseResourceLite(Fcb->PagingIoResource );										 
	if (Fcb->Resource)
		ExReleaseResourceLite(Fcb->Resource );					   

	FsRtlExitFileSystem() ;
}

