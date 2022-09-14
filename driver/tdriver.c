/*++

Module Name:

    tdriver.c

Abstract:

    Main module for the Ob and Ps sample code

Notice:
    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
    (http://www.microsoft.com/opensource/licenses.mspx)


--*/

#include "pch.h"

#include "tdriver.h"

#define malloc(Size) ExAllocatePoolWithTag(NonPagedPool, (Size), 'abc1');
#define free(pointer)         ExFreePoolWithTag((pointer), 'abc1');

//#define CAPACITY 50000 // Size of the Hash Table


HANDLE mproc = NULL;


#define SIZE 500
int indexesofh[SIZE];

struct DataItem {
    int data;
    LONG64 key;
};

struct DataItem* hashArray[SIZE];
struct DataItem* dummyItem;
struct DataItem* item;

int hashCode(LONG64 key) {
    return key % SIZE;
}

struct DataItem* search(LONG64 key) {
    //get the hash 
    int hashIndex = hashCode(key);

    //move in array until an empty 
    while (hashArray[hashIndex] != NULL) {

        if (hashArray[hashIndex]->key == key)
            return hashArray[hashIndex];

        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }

    return NULL;
}

int insert(LONG64 key, int data) {

    struct DataItem* item2 = (struct DataItem*)malloc(sizeof(struct DataItem));
    item2->data = data;
    item2->key = key;

    //get the hash 
    int hashIndex = hashCode(key);

    //move in array until an empty or deleted cell
    while (hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1) {
        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }

    hashArray[hashIndex] = item2;
    return hashIndex;
}

struct DataItem* delete(struct DataItem* item2) {
    LONG64 key = item2->key;

    //get the hash 
    int hashIndex = hashCode(key);

    //move in array until an empty
    while (hashArray[hashIndex] != NULL) {

        if (hashArray[hashIndex]->key == key) {
            struct DataItem* temp = hashArray[hashIndex];

            //assign a dummy item at deleted position
            hashArray[hashIndex] = dummyItem;
            return temp;
        }

        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }

    return NULL;
}

PKEVENT eventD, eventD2;
wchar_t *buffer;
BOOLEAN Iscontrolled = FALSE;


int II = 0, JJ = 0;
PTD_PROTECTNAME_INPUT ProtectNameInput1 = NULL;
//
// Process notify routines.
//

BOOLEAN TdProcessNotifyRoutineSet2 = FALSE;


// allow filter the requested access
BOOLEAN TdbProtectName = FALSE;
BOOLEAN TdbRejectName = FALSE;

//
// Function declarations
//
DRIVER_INITIALIZE  DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH TdDeviceCreate;
_Dispatch_type_(IRP_MJ_READ) DRIVER_DISPATCH TdDeviceRead;
_Dispatch_type_(IRP_MJ_WRITE) DRIVER_DISPATCH TdDeviceWrite;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH TdDeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH TdDeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH TdDeviceControl;

DRIVER_UNLOAD   TdDeviceUnload;
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

QUERY_INFO_PROCESS ZwQueryInformationProcess;
//Function Definition


VOID
TdCreateProcessNotifyRoutine2 (
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    //NTSTATUS Status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
    DbgPrint("ProcessCreate...\n");
    if (CreateInfo != NULL)
    {

        /* DbgPrintEx(
             DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
             "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
             "    command line %wZ\n"
             "    file name %wZ (FileOpenNameAvailable: %d)\n",
             Process,
             (PVOID)ProcessId,
             (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
             (ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
             CreateInfo->CommandLine,
             CreateInfo->ImageFileName,
             CreateInfo->FileOpenNameAvailable
         );
         */
         // Search for matching process to protect only if filtering
       /*  if (TdbProtectName) {
             if (CreateInfo->CommandLine != NULL)
             {
                 Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

                 if (Status == STATUS_SUCCESS) {
                     DbgPrintEx (
                         DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: PROTECTING process %p (ID 0x%p)\n",
                         Process,
                         (PVOID)ProcessId
                     );
                 }
             }

         }

         // Search for matching process to reject process creation
         if (TdbRejectName) {
             if (CreateInfo->CommandLine != NULL)
             {*/
             //Status = TdCheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);
             //CHAR buffer[] = { 'T', 'e', 's', 't', '\0'};    //  for example
           //  ULONG bufferSize = sizeof(buffer);


        if (TRUE) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: REJECTING process %p (ID 0x%p)\n",
                Process,
                (PVOID)ProcessId
            );  
            BOOLEAN Iscontrolled2 = TRUE;
            KeAcquireGuardedMutex(&TdCallbacksMutex);
            Iscontrolled2 = Iscontrolled;
            KeReleaseGuardedMutex(&TdCallbacksMutex);

         
            //  UNICODE_STRING ProcessName;
              //GetProcessImageName(ProcessId, &ProcessName);
              //wcsncpy(buffer, ProcessName.Buffer, ProcessName.Length);
              //buffer[0] = 'A';

           //   RtlCopyBytes(ProtectNameInput1->Name, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
             // ProtectNameInput1->parentID = CreateInfo->ParentProcessId;
          //    KeSetEvent(eventD, IO_NO_INCREMENT, FALSE);
                          //KeClearEvent(eventD2);
                    
         
                
                /*   op = operation[II];*/
                //KeWaitForSingleObject(eventD, Executive, KernelMode, FALSE, &timeout);

              //  KeReleaseGuardedMutex(&TdCallbacksMutex);


                    INT64 op = 0;

               //  KeClearEvent(eventD2);
            if (Iscontrolled2)
            {
                //op = 1;
                    LARGE_INTEGER timeout;
                    //timeout.QuadPart = -10000 * 10000;
                    //KeAcquireGuardedMutex(&TdCallbacksMutex);

                   // KeReleaseGuardedMutex(&TdCallbacksMutex);
                   
                    timeout.QuadPart = -10000 * 40000;

                   
                    KeAcquireGuardedMutex(&TdCallbacksMutex);
                  //  char* strk;
                    mproc = ProcessId;
                    //strk = int2str((LONGLONG)ProcessId);


                    //KeAcquireGuardedMutex(&TdCallbacksMutex);
                /*    indexesofh[JJ] = insert((LONG64)mproc, 2);
                    JJ++;

                    //}
                    if (JJ > SIZE)
                    {
                        JJ = 0;
                    }
                    */
                    KeReleaseGuardedMutex(&TdCallbacksMutex);


                    
                  //  if (op == 2)
                    //{      
                    
                        KeSetEvent(eventD2, IO_NO_INCREMENT, FALSE);
                        KeClearEvent(eventD);
                        KeWaitForSingleObject(eventD, Executive, KernelMode, FALSE, &timeout);
                        KeAcquireGuardedMutex(&TdCallbacksMutex);
                        struct DataItem* ch = search((LONG64)mproc);
                        if (ch != NULL)
                        {
                            op = ch->data;
                            ExFreePoolWithTag(ch, 'abc1');
                        }
                        KeReleaseGuardedMutex(&TdCallbacksMutex);
                    //}
                        //KeWaitForSingleObject(eventD, Executive, KernelMode, FALSE, &timeout);


                  //  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hello %d %d", op, prc);
                      
                        if (op == TDProtectName_Reject)
            {

                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            }
                    }
            
        }
    }

   /* }
    }
    else
    {
        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) destroyed\n",
            Process,
            (PVOID)ProcessId
        );
    }*/
}

//
// DriverEntry
//

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING (TD_NT_DEVICE_NAME);
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);
    PDEVICE_OBJECT Device = NULL;
    BOOLEAN SymLinkCreated = FALSE;
    USHORT CallbackVersion;

    
    UNREFERENCED_PARAMETER (RegistryPath);

    buffer = ExAllocatePoolWithTag(NonPagedPool, NAME_SIZE * 10, 'abc');
    if(buffer != NULL)
    buffer[0] = (wchar_t)0;
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: Driver loaded. Use ed nt!Kd_IHVDRIVER_Mask f (or 7) to enable more traces\n");

    CallbackVersion = ObGetFilterVersion();

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObCallbackTest: DriverEntry: Callback version 0x%hx\n", CallbackVersion);

    //
    // Initialize globals.
    //

    KeInitializeGuardedMutex (&TdCallbacksMutex);
    
    //
    // Create our device object.
    //

    Status = IoCreateDevice (                    
        DriverObject,                 // pointer to driver object
        0,                            // device extension size
        &NtDeviceName,                // device name
        FILE_DEVICE_UNKNOWN,          // device type
        0,                            // device characteristics
        FALSE,                        // not exclusive
        &Device);                     // returned device object pointer

    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }

    TD_ASSERT (Device == DriverObject->DeviceObject);

    //
    // Set dispatch routines.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = TdDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = TdDeviceRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = TdDeviceWrite;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = TdDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = TdDeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdDeviceControl;
    DriverObject->DriverUnload                         = TdDeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //
   // DriverObject->DeviceObject->Flags
   //DriverObject->DeviceObject->Flags
    DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DriverObject->Flags |= DO_BUFFERED_IO;

  //  DriverObject->DeviceObject->Flags |= DO_DIRECT_IO;// METHOD_NEITHER;
    Status = IoCreateSymbolicLink (&DosDevicesLinkName, &NtDeviceName);
    
    if (! NT_SUCCESS(Status))
    {
        goto Exit;
    }

    SymLinkCreated = TRUE;

    //
    // Set process create routines.
    //
    UNICODE_STRING      evname = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\WRObCallback");   //  Must be with DOS prefix: \??\C:\MyFolder\logs.txt

    HANDLE event1;
   eventD =  IoCreateNotificationEvent(&evname, &event1);
   if (eventD != NULL)
   {
       KeInitializeEvent(eventD, SynchronizationEvent, FALSE);
       KeClearEvent(eventD);
   }

   UNICODE_STRING      evname2 = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\WRObCallback2");   //  Must be with DOS prefix: \??\C:\MyFolder\logs.txt

   HANDLE event2;
   eventD2 = IoCreateNotificationEvent(&evname2, &event2);
   if (eventD2 != NULL)
   {
       KeInitializeEvent(eventD2, SynchronizationEvent, FALSE);
       KeClearEvent(eventD2);
   }

  
   if (event1 == NULL)
   {
       DbgPrint("error event1");
       goto Exit;
}
    Status = PsSetCreateProcessNotifyRoutineEx (
        TdCreateProcessNotifyRoutine2,
        FALSE
    );

    if (! NT_SUCCESS(Status))
    {
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: PsSetCreateProcessNotifyRoutineEx(2) returned 0x%x\n", Status);
        goto Exit;
    }

    TdProcessNotifyRoutineSet2 = TRUE;
    for (int c = 0; c < SIZE; c++)
    {
        indexesofh[c] = 0;
    }
Exit:

    if (!NT_SUCCESS (Status))
    {
        if (TdProcessNotifyRoutineSet2 == TRUE)
        {
            Status = PsSetCreateProcessNotifyRoutineEx (
                TdCreateProcessNotifyRoutine2,
                TRUE
            );

            TD_ASSERT (Status == STATUS_SUCCESS);

            TdProcessNotifyRoutineSet2 = FALSE;
        }

        if (SymLinkCreated == TRUE)
        {
            IoDeleteSymbolicLink (&DosDevicesLinkName);
        }

        if (Device != NULL)
        {
            IoDeleteDevice (Device);
        }
    }

    return Status;
}

//
// Function:
//
//     TdDeviceUnload
//
// Description:
//
//     This function handles driver unloading. All this driver needs to do 
//     is to delete the device object and the symbolic link between our 
//     device name and the Win32 visible name.
//

VOID
TdDeviceUnload (
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING (TD_DOS_DEVICES_LINK_NAME);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

    //
    // Unregister process notify routines.
    //

    if (TdProcessNotifyRoutineSet2 == TRUE)
    {
        Status = PsSetCreateProcessNotifyRoutineEx (
            TdCreateProcessNotifyRoutine2,
            TRUE
        );

        TD_ASSERT (Status == STATUS_SUCCESS);

        TdProcessNotifyRoutineSet2 = FALSE;
    }

    // remove filtering and remove any OB callbacks
    TdbProtectName = FALSE;
    Status = TdDeleteProtectNameCallback();
    TD_ASSERT (Status == STATUS_SUCCESS);

    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    Status = IoDeleteSymbolicLink (&DosDevicesLinkName);
    if (Status != STATUS_INSUFFICIENT_RESOURCES) {
        //
        // IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
        //
    
        TD_ASSERT (NT_SUCCESS (Status));

    }


    //
    // Delete our device object.
    //

    IoDeleteDevice (DriverObject->DeviceObject);
}

//
// Function:
//
//     TdDeviceCreate
//
// Description:
//
//     This function handles the 'create' irp.
//


NTSTATUS
TdDeviceCreate (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);
    DeviceObject->Flags=TD_IOCTL_PROTECT_NAME_CALLBACK;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
TdDeviceRead(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
   
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
TdDeviceWrite(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


//
// Function:
//
//     TdDeviceClose
//
// Description:
//
//     This function handles the 'close' irp.
//

NTSTATUS
TdDeviceClose (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);
   
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Function:
//
//     TdDeviceCleanup
//
// Description:
//
//     This function handles the 'cleanup' irp.
//

NTSTATUS
TdDeviceCleanup (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER (DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// TdControlProtectName
//
//int pid;


NTSTATUS TdControlProtectName (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack = NULL;
    ULONG InputBufferLength = 0;

    UNREFERENCED_PARAMETER (DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    
    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TdControlProtectName: Entering\n");
   
    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputBufferLength < sizeof (TD_PROTECTNAME_INPUT))
    {
        Status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }
   

    ProtectNameInput1 = (PTD_PROTECTNAME_INPUT)Irp->AssociatedIrp.SystemBuffer;
  //  pid = pProtectNameInput->PID;
    //RtlCopyMemory(Irp->UserBuffer, "Hi....", 7);
  /*  Status = TdProtectNameCallback(pProtectNameInput);

    switch (pProtectNameInput->Operation) {
        case TDProtectName_Protect:
            // Begin filtering access rights
            TdbProtectName = TRUE;
            TdbRejectName = FALSE;
            break;
    
        case TDProtectName_Reject:
            // Begin reject process creation on match
            TdbProtectName = FALSE;
            TdbRejectName = TRUE;
            break;
    }
    */

Exit:
    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_PROTECTNAME: Status %x\n", Status);

    return Status;
}

//
// TdControlUnprotect
//

NTSTATUS TdControlUnprotect (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    // PIO_STACK_LOCATION IrpStack = NULL;
    // ULONG InputBufferLength = 0;

    UNREFERENCED_PARAMETER (DeviceObject);
    UNREFERENCED_PARAMETER (Irp);

    // IrpStack = IoGetCurrentIrpStackLocation (Irp);
    // InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // No need to check length of passed in parameters as we do not need any information from that

    // do not filter requested access
    Status = TdDeleteProtectNameCallback();
    if (Status != STATUS_SUCCESS) {
        DbgPrintEx (
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "ObCallbackTest: TdDeleteProtectNameCallback:  status 0x%x\n", Status);
        }
    TdbProtectName = FALSE;
    TdbRejectName = FALSE;

//Exit:
    DbgPrintEx (
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_UNPROTECT: exiting - status 0x%x\n", Status);

    return Status;
}


//
// Function:
//
//     TdDeviceControl
//
// Description:
//
//     This function handles 'control' irp.
//
NTSTATUS
TdDeviceControl (
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{

    KeAcquireGuardedMutex(&TdCallbacksMutex);
    Iscontrolled = TRUE;
    KeReleaseGuardedMutex(&TdCallbacksMutex);  //  KeAcquireGuardedMutex(&TdCallbacksMutex);
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status;
    //PEPROCESS pep = NULL;
    //PKAPC_STATE st = NULL;
    UNREFERENCED_PARAMETER(DeviceObject);
    Status = STATUS_SUCCESS;
    Irp->Flags |= METHOD_BUFFERED;
   // if (Iscontrolled)
    //{
       /* LARGE_INTEGER timeout;
        timeout.LowPart = 40000;
        */
    //}
    //TdControlProtectName(DeviceObject, Irp);
    IrpStack = IoGetCurrentIrpStackLocation (Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;
     // RtlCopyBytes(buffer, L"Hi....", sizeof(L"Hi...."));
      //  Irp->AssociatedIrp.SystemBuffer = buffer;
        
    
       /* PCHAR               buffer1 = NULL;
        buffer1 = Irp->UserBuffer;
        */


//KeDetachProcess();
        //   wcscpy_s((PWCHAR)Irp->MdlAddress, 7, L"hi....");
    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl: entering - ioctl code 0x%x\n", Ioctl);

    switch (Ioctl)
    {
    case TD_IOCTL_PROTECT_NAME_CALLBACK:
        

       // Status = TdControlProtectName (DeviceObject, Irp);     
        IrpStack->Parameters.Write.Length = IrpStack->Parameters.DeviceIoControl.OutputBufferLength = 8;
        IrpStack->Parameters.Read.Length = IrpStack->Parameters.DeviceIoControl.InputBufferLength = sizeof(TD_PROTECTNAME_INPUT);

        Irp->IoStatus.Information = 8;
 
        // PsLookupProcessByProcessId((HANDLE)pid, &pep);
        // KeStackAttachProcess(pep, st);
        // Irp->AssociatedIrp.SystemBuffer = NULL;
    //     buffer[0] = 'A';
//        wcscpy_s(buffer, 10, L"Hello!!!!!"); 
        KeAcquireGuardedMutex(&TdCallbacksMutex);
        *((HANDLE*)Irp->AssociatedIrp.SystemBuffer) = (HANDLE)mproc;
        if (indexesofh[II]!= 0)
        {
            *((HANDLE*)Irp->AssociatedIrp.SystemBuffer) = (HANDLE)indexesofh[II];
            II++;
        }
       
        if (II > SIZE)
        {
            II = 0;
        }
        KeReleaseGuardedMutex(&TdCallbacksMutex);
        

        break;

    case TD_IOCTL_UNPROTECT_CALLBACK:

        //Status = TdControlUnprotect (DeviceObject, Irp);
       
      //  IrpStack->Parameters.Read.Length = IrpStack->Parameters.DeviceIoControl.InputBufferLength = sizeof(TD_PROTECTNAME_INPUT);
        KeAcquireGuardedMutex(&TdCallbacksMutex);
        PTD_PROTECTNAME_INPUT  pProtectNameInput = (PTD_PROTECTNAME_INPUT)Irp->AssociatedIrp.SystemBuffer;
        
    //    char *strk = int2str((LONGLONG)pProtectNameInput->PID);
          //  _snprintf(strk, 200, "%llu", (DWORD64)pProtectNameInput->PID);
           // HANDLE pid = pProtectNameInput->PID;
      //      char* strv = int2str(pProtectNameInput->Operation);
            //_snprintf(strv, 200, "%llu", (DWORD64)pProtectNameInput->Operation);
           // if (pid > 0)
           //{
                insert((LONGLONG)pProtectNameInput->PID, pProtectNameInput->Operation);
           //  
            KeReleaseGuardedMutex(&TdCallbacksMutex);
           // KeClearEvent(eventD);
            KeSetEvent(eventD, IO_NO_INCREMENT, FALSE);
           
       
        //{}
        
    
           
            
            Irp->IoStatus.Information = 0;

 break;

    default:
        DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "TdDeviceControl: unrecognized ioctl code 0x%x\n", Ioctl);
        break;
    }

    //
    // Complete the irp and return.
    //
 Irp->IoStatus.Status = Status;
    IoCompleteRequest (Irp, IO_NO_INCREMENT);

    DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TdDeviceControl leaving - status 0x%x\n", Status);
    //KeReleaseGuardedMutex(&TdCallbacksMutex);
   // KeSetEvent(eventD, IO_NO_INCREMENT, FALSE);

    return Status;
}
