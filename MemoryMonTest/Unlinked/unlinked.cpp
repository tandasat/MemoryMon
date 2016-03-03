// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver.
//
#include "unlinked.h"
#include <fltKernel.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "exclusivity.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Break point that works only when a debugger is enabled
#define UNLINKED_UNLINKED_DBG_BREAK() \
  if (KD_DEBUGGER_NOT_PRESENT) {      \
  } else {                            \
    __debugbreak();                   \
  }                                   \
  reinterpret_cast<void *>(0)

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG kUnlinkedPoolTag = 'knlu';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct LdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_Initialization_order_links;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS UnlinkedpHideDriver(_In_ PDRIVER_OBJECT driver_object);

static VOID UnlinkedpProcessNotifyRoutineEx(
    _Inout_ PEPROCESS process, _In_ HANDLE process_id,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, UnlinkedpHideDriver)
#pragma alloc_text(PAGE, UnlinkedpProcessNotifyRoutineEx)
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
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  UNLINKED_UNLINKED_DBG_BREAK();

  auto status =
      PsSetCreateProcessNotifyRoutineEx(UnlinkedpProcessNotifyRoutineEx, FALSE);
  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "[Unlinked] Failed to install a notification routine.\n");
    return status;
  }

  status = UnlinkedpHideDriver(driver_object);
  if (!NT_SUCCESS(status)) {
    PsSetCreateProcessNotifyRoutineEx(UnlinkedpProcessNotifyRoutineEx, TRUE);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "[Unlinked] Failed to hide the driver.\n");
    return status;
  }

  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             "[Unlinked] The unlinked driver was installed (DriverObject = %p, "
             "Notification = %p)\n",
             driver_object, UnlinkedpProcessNotifyRoutineEx);
  return status;
}

// Unlink the driver object from the PsLoadedModuleList
#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ static NTSTATUS UnlinkedpHideDriver(
    PDRIVER_OBJECT driver_object) {
  const auto exlusivity = ExclGainExclusivity();
  if (!exlusivity) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }
#pragma warning(push)
#pragma warning(disable : 28175)
  auto module =
      reinterpret_cast<LdrDataTableEntry *>(driver_object->DriverSection);
#pragma warning(pop)
  RemoveEntryList(&module->in_load_order_links);
  ExclReleaseExclusivity(exlusivity);
  return STATUS_SUCCESS;
}
#pragma warning(pop)

// DbgPrints when a process is created
_Use_decl_annotations_ static void UnlinkedpProcessNotifyRoutineEx(
    PEPROCESS process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO create_info) {
  UNREFERENCED_PARAMETER(process);
  PAGED_CODE();

  if (create_info) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               "[Unlinked] PID %5Iu is being created: %wZ\n",
               reinterpret_cast<ULONG_PTR>(process_id),
               create_info->ImageFileName);
  }
}

}  // extern "C"
