// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver.
//
#include "no_image.h"

#include <fltKernel.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Break point that works only when a debugger is enabled
#define NOIMAGE_NO_IMAGE_DBG_BREAK() \
  if (KD_DEBUGGER_NOT_PRESENT) {     \
  } else {                           \
    __debugbreak();                  \
  }                                  \
  reinterpret_cast<void *>(0)

// Converts x to L"x"
#define NOIMAGE_NO_IMAGE_P_TOSTRINGW2(x) L#x
#define NOIMAGE_NO_IMAGE_P_TOSTRINGW1(x) NOIMAGE_NO_IMAGE_P_TOSTRINGW2(x)

// Wrapper of MmGetSystemRoutineAddress()
#define NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(proc_name) \
  reinterpret_cast<decltype(&proc_name)>(                     \
      NoImagepGetSystemProcAddress(NOIMAGE_NO_IMAGE_P_TOSTRINGW1(proc_name)))

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG kNoImagePoolTag = 'mgin';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

using DbgPrintExType = decltype(&DbgPrintEx);
using ExAllocatePoolWithTagType = decltype(&ExAllocatePoolWithTag);
using ExFreePoolWithTagType = decltype(&ExFreePoolWithTag);
using ExQueueWorkItemType = decltype(&ExQueueWorkItem);
using KeDelayExecutionThreadType = decltype(&KeDelayExecutionThread);
using KeInitializeDpcType = decltype(&KeInitializeDpc);
using KeInsertQueueDpcType = decltype(&KeInsertQueueDpc);
using memcpyType = decltype(&memcpy);

struct NoImageContext {
  PBOOLEAN KdDebuggerNotPresent;
  DbgPrintExType DbgPrintEx;
  ExAllocatePoolWithTagType ExAllocatePoolWithTag;
  ExFreePoolWithTagType ExFreePoolWithTag;
  ExQueueWorkItemType ExQueueWorkItem;
  KeDelayExecutionThreadType KeDelayExecutionThread;
  KeInitializeDpcType KeInitializeDpc;
  KeInsertQueueDpcType KeInsertQueueDpc;
  memcpyType memcpy;

  KDPC dpc;
  PKDEFERRED_ROUTINE dpc_routine;
  WORK_QUEUE_ITEM work_item;
  PWORKER_THREAD_ROUTINE workI_iem_routine;
  NoImageContext *old_context;
  char log_format[260];
  UCHAR code[1];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

DRIVER_INITIALIZE DriverEntry;

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS NoImagepInstallContexts();

_IRQL_requires_max_(PASSIVE_LEVEL) static void *NoImagepGetSystemProcAddress(
    _In_ const wchar_t *proc_name);

static KDEFERRED_ROUTINE NoImagepContextDpcRoutine;

static WORKER_THREAD_ROUTINE NoImagepContextWorkItemRoutine;

static void NoImagepContextZZZ();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, NoImagepInstallContexts)
#pragma alloc_text(INIT, NoImagepGetSystemProcAddress)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(driver_object);
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  NOIMAGE_NO_IMAGE_DBG_BREAK();

  auto status = NoImagepInstallContexts();
  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "[NoImageContext] Failed to install context(s).\n");
    return status;
  }
  return STATUS_CANCELLED;
}

// Install at least one context
_Use_decl_annotations_ static NTSTATUS NoImagepInstallContexts() {
  PAGED_CODE();

#pragma warning(push)
#pragma warning(disable : 30030)
  const auto noImage_context = reinterpret_cast<NoImageContext *>(
      ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE, kNoImagePoolTag));
#pragma warning(pop)

  if (!noImage_context) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }
  RtlZeroMemory(noImage_context, PAGE_SIZE);

  // Initialize all fields
  noImage_context->KdDebuggerNotPresent = KdDebuggerNotPresent;
  noImage_context->DbgPrintEx =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(DbgPrintEx);
  noImage_context->ExAllocatePoolWithTag =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(ExAllocatePoolWithTag);
  noImage_context->ExFreePoolWithTag =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(ExFreePoolWithTag);
  noImage_context->ExQueueWorkItem =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(ExQueueWorkItem);
  noImage_context->KeDelayExecutionThread =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(KeDelayExecutionThread);
  noImage_context->KeInitializeDpc =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(KeInitializeDpc);
  noImage_context->KeInsertQueueDpc =
      NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(KeInsertQueueDpc);
  noImage_context->memcpy = NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS(memcpy);
  if (!noImage_context->KdDebuggerNotPresent || !noImage_context->DbgPrintEx ||
      !noImage_context->ExAllocatePoolWithTag ||
      !noImage_context->ExFreePoolWithTag ||
      !noImage_context->ExQueueWorkItem ||
      !noImage_context->KeDelayExecutionThread ||
      !noImage_context->KeInitializeDpc || !noImage_context->KeInsertQueueDpc ||
      !noImage_context->memcpy) {
    return STATUS_PROCEDURE_NOT_FOUND;
  }

  auto status = RtlStringCchCopyA(
      noImage_context->log_format, RTL_NUMBER_OF(noImage_context->log_format),
      "[NoImageContext] Type= %c, Context = %p, DPC = %p, WorkItem = %p\n");
  if (!NT_SUCCESS(status)) {
    return status;
  }

  const auto code_size = reinterpret_cast<ULONG_PTR>(NoImagepContextZZZ) -
                         reinterpret_cast<ULONG_PTR>(NoImagepContextDpcRoutine);
  const auto offset_to_work_item_routine =
      reinterpret_cast<ULONG_PTR>(NoImagepContextWorkItemRoutine) -
      reinterpret_cast<ULONG_PTR>(NoImagepContextDpcRoutine);
  RtlCopyMemory(noImage_context->code, NoImagepContextDpcRoutine, code_size);

  noImage_context->dpc_routine =
      reinterpret_cast<PKDEFERRED_ROUTINE>(&noImage_context->code[0]);
  noImage_context->workI_iem_routine = reinterpret_cast<PWORKER_THREAD_ROUTINE>(
      noImage_context->code + offset_to_work_item_routine);

  ExInitializeWorkItem(&noImage_context->work_item,
                       noImage_context->workI_iem_routine, noImage_context);
  KeInitializeDpc(&noImage_context->dpc, noImage_context->dpc_routine,
                  noImage_context);

  // Queue a DPC
  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, noImage_context->log_format,
             'I', noImage_context, noImage_context->dpc.DeferredRoutine,
             noImage_context->work_item.WorkerRoutine);
  KeInsertQueueDpc(&noImage_context->dpc, nullptr, nullptr);
  return STATUS_SUCCESS;
}

// Gets a procedure address and returns it with an appropriate type
_Use_decl_annotations_ static void *NoImagepGetSystemProcAddress(
    const wchar_t *proc_name) {
  PAGED_CODE();

  UNICODE_STRING proc_name_U = {};
  RtlInitUnicodeString(&proc_name_U, proc_name);
  return MmGetSystemRoutineAddress(&proc_name_U);
}

#pragma region Context code that cannot reference any exports directly
#pragma optimize("", off)
#pragma check_stack(off)
#pragma runtime_checks("", off)

// Queues a workitem
_Use_decl_annotations_ static void NoImagepContextDpcRoutine(
    KDPC *dpc, PVOID deferred_context, PVOID system_argument1,
    PVOID system_argument2) {
  UNREFERENCED_PARAMETER(dpc);
  UNREFERENCED_PARAMETER(system_argument1);
  UNREFERENCED_PARAMETER(system_argument2);

  NT_ASSERT(deferred_context);
  const auto noImage_context =
      reinterpret_cast<NoImageContext *>(deferred_context);
  if (!*noImage_context->KdDebuggerNotPresent) {
    // __debugbreak();
  }

  noImage_context->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                              noImage_context->log_format, 'D', noImage_context,
                              noImage_context->dpc.DeferredRoutine,
                              noImage_context->work_item.WorkerRoutine);
  noImage_context->ExQueueWorkItem(&noImage_context->work_item,
                                   DelayedWorkQueue);
}

// Waits sometime, re-allocates a new context and queues a DPC
_Use_decl_annotations_ static void NoImagepContextWorkItemRoutine(
    PVOID parameter) {
  NT_ASSERT(parameter);
  auto noImage_context = reinterpret_cast<NoImageContext *>(parameter);
  if (!*noImage_context->KdDebuggerNotPresent) {
    // __debugbreak();
  }
  noImage_context->DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                              noImage_context->log_format, 'W', noImage_context,
                              noImage_context->dpc.DeferredRoutine,
                              noImage_context->work_item.WorkerRoutine);

  // Sleep some time
  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000ll * 5000);  // msec
  noImage_context->KeDelayExecutionThread(KernelMode, FALSE, &interval);

  // Replace the context with a newly allocated one
  if (noImage_context->old_context) {
    noImage_context->ExFreePoolWithTag(noImage_context->old_context,
                                       kNoImagePoolTag);
    noImage_context->old_context = nullptr;
  }

  const auto new_context =
      reinterpret_cast<NoImageContext *>(noImage_context->ExAllocatePoolWithTag(
          NonPagedPoolExecute, PAGE_SIZE, kNoImagePoolTag));
  if (new_context) {
    noImage_context->memcpy(new_context, noImage_context, PAGE_SIZE);

    const auto offset_to_work_item_routine =
        reinterpret_cast<ULONG_PTR>(NoImagepContextWorkItemRoutine) -
        reinterpret_cast<ULONG_PTR>(NoImagepContextDpcRoutine);

    new_context->dpc_routine =
        reinterpret_cast<PKDEFERRED_ROUTINE>(&new_context->code[0]);
    new_context->workI_iem_routine = reinterpret_cast<PWORKER_THREAD_ROUTINE>(
        new_context->code + offset_to_work_item_routine);

    // ExInitializeWorkItem begin; since ExInitializeWorkItem is a macro, we
    // cannot get its exported address
    new_context->work_item.WorkerRoutine = new_context->workI_iem_routine;
    new_context->work_item.Parameter = new_context;
    new_context->work_item.List.Flink = nullptr;

    new_context->KeInitializeDpc(&new_context->dpc, new_context->dpc_routine,
                                 new_context);
    new_context->old_context = noImage_context;
    noImage_context = new_context;
  }

  // Queue a new DPC
  noImage_context->KeInsertQueueDpc(&noImage_context->dpc, nullptr, nullptr);
}

// End of NoImageContext functions. Do not change names, in particular ZZZ to
// place it at after other NoImageContext functions as VC order functions based
// on their names.
static void NoImagepContextZZZ() {}

#pragma runtime_checks("", restore)
#pragma check_stack()
#pragma optimize("", on)
#pragma endregion

#undef NOIMAGE_NO_IMAGE_P_GET_SYSTEM_PROC_ADDRESS
#undef NOIMAGE_NO_IMAGE_P_TOSTRINGW1
#undef NOIMAGE_NO_IMAGE_P_TOSTRINGW2

}  // extern "C"
