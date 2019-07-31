#include "S_Ctx.h"

static NTSTATUS iCtx_CreateStreamContext(PFLT_RELATED_OBJECTS FltObjects, PSTREAM_CONTEXT *StreamContext) ;


VOID
SC_LOCK(PSTREAM_CONTEXT SC, PKIRQL OldIrql)
{
    if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        SC_iLOCK(SC->Resource) ;
    }
    else
    {
        KeAcquireSpinLock(&SC->Spinlock, OldIrql) ;
    }
}

VOID
SC_UNLOCK(PSTREAM_CONTEXT SC, KIRQL OldIrql)
{
    if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        SC_iUNLOCK(SC->Resource) ;
    }
    else
    {
        KeReleaseSpinLock(&SC->Spinlock, OldIrql) ;
    }
}

/** 
 * [Ctx_FindOrCreateStreamContext This routine finds the stream context for the target stream Optionally, if the context does not exist this routing creates a new one and attaches the context to the stream.]
 * @Author   zzc
 * @DateTime 2019年7月9日T7:01:28+0800
 * @param    Cbd                      [Supplies a pointer to the callbackData which declares the requested operation.]
 * @param    FltObjects               [description]
 * @param    CreateIfNotFound         [Supplies if the stream must be created if missing]
 * @param    _StreamContext           [Returns the stream context]
 * @param    ContextCreated           [Returns if a new context was created]
 * @return                            [NTSTATUS]
 */
NTSTATUS Ctx_FindOrCreateStreamContext (PFLT_CALLBACK_DATA Cbd,PFLT_RELATED_OBJECTS FltObjects,BOOLEAN CreateIfNotFound, PSTREAM_CONTEXT *_StreamContext,PBOOLEAN ContextCreated)
{
    NTSTATUS status=STATUS_NOT_FOUND;
    PSTREAM_CONTEXT streamContext = NULL;
    PSTREAM_CONTEXT oldStreamContext = NULL;

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		return status;
	}

	PAGED_CODE();

    *_StreamContext = NULL;
    if (ContextCreated != NULL) *ContextCreated = FALSE;

    //  First try to get the stream context.
    status = FltGetStreamContext( Cbd->Iopb->TargetInstance,Cbd->Iopb->TargetFileObject,&streamContext );
    if (!NT_SUCCESS( status ) &&(status == STATUS_NOT_FOUND) &&CreateIfNotFound)
    {
        status = iCtx_CreateStreamContext(FltObjects, &streamContext );
        if (!NT_SUCCESS( status ))
            return status;
        status = FltSetStreamContext(Cbd->Iopb->TargetInstance,Cbd->Iopb->TargetFileObject,FLT_SET_CONTEXT_KEEP_IF_EXISTS,streamContext,&oldStreamContext );

        if (!NT_SUCCESS( status ))
        {
            FltReleaseContext(streamContext);

            if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
            {
                //  FltSetStreamContext failed for a reason other than the context already
                //  existing on the stream. So the object now does not have any context set
                //  on it. So we return failure to the caller.
                return status;
            }
            streamContext = oldStreamContext;
            status = STATUS_SUCCESS;
        }
        else
        {
            if (ContextCreated != NULL) *ContextCreated = TRUE;
        }
    }
    *_StreamContext = streamContext;

    return status;
}

/** 
 * [iCtx_CreateStreamContext This routine creates a new stream context]
 * @Author   fanyusen
 * @DateTime 2019年7月9日T7:12:55+0800
 * @param    FltObjects               [description]
 * @param    _StreamContext           [Returns the stream context]
 * @return                            [Status]
 */
NTSTATUS iCtx_CreateStreamContext (PFLT_RELATED_OBJECTS FltObjects,PSTREAM_CONTEXT *_StreamContext)
{
    NTSTATUS status;
    PSTREAM_CONTEXT streamContext;

    PAGED_CODE();

//分配一的一片动态内存区。这个调用传入需要的内存空间的大小 并返回一个内存空间指针。
    status = FltAllocateContext( FltObjects->Filter,FLT_STREAM_CONTEXT,STREAM_CONTEXT_SIZE,NonPagedPool,&streamContext );
    if (!NT_SUCCESS( status ))
    {
        return status;
    }

    //  Initialize the newly created context
    RtlZeroMemory( streamContext, STREAM_CONTEXT_SIZE );

    streamContext->Resource = ExAllocatePoolWithTag( NonPagedPool, sizeof( ERESOURCE ),RESOURCE_TAG );
    if (streamContext->Resource == NULL)
    {
        FltReleaseContext( streamContext );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ExInitializeResourceLite( streamContext->Resource );

    KeInitializeSpinLock(&streamContext->Spinlock) ;

    *_StreamContext = streamContext;

    return STATUS_SUCCESS;
}


	   
								   
NTSTATUS Ctx_UpdateNameInStreamContext (__in PUNICODE_STRING DirectoryName,__inout PSTREAM_CONTEXT StreamContext)
{
          NTSTATUS status = STATUS_SUCCESS ;

          PAGED_CODE();

           //Free any existing name
           if (StreamContext->FileName.Buffer != NULL) 
           {
               ExFreePoolWithTag( StreamContext->FileName.Buffer,STRING_TAG );
               
               StreamContext->FileName.Length = StreamContext->FileName.MaximumLength = 0;
               StreamContext->FileName.Buffer = NULL;
           }

           //Allocate and copy off the directory name
          StreamContext->FileName.MaximumLength = DirectoryName->MaximumLength;
          StreamContext->FileName.Length=DirectoryName->Length;
          StreamContext->FileName.Buffer = ExAllocatePoolWithTag( PagedPool,
                                                   StreamContext->FileName.MaximumLength,
                                                   STRING_TAG );
           if (StreamContext->FileName.Buffer == NULL) 
           {
               return STATUS_INSUFFICIENT_RESOURCES;
           }

          memset(StreamContext->FileName.Buffer,0,StreamContext->FileName.MaximumLength);

          RtlCopyMemory(StreamContext->FileName.Buffer,DirectoryName->Buffer,DirectoryName->Length);
           
           //RtlCopyUnicodeString(&StreamContext->FileName, DirectoryName);

           return status;
}
							   
								   