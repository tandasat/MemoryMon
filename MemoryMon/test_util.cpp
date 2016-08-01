// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements test utility functions.

#include "test_util.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    TestUtilpMiPurgeTransitionList();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS TestUtilpMmFlushAllPages();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    TestUtilpMmEmptyAllWorkingSets();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    TestUtilpExecuteSystemMemoryListOperation(_In_ ULONG operation_number);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, TestUtilPageOut)
#pragma alloc_text(PAGE, TestUtilpExecuteSystemMemoryListOperation)
#pragma alloc_text(PAGE, TestUtilpMmEmptyAllWorkingSets)
#pragma alloc_text(PAGE, TestUtilpMmFlushAllPages)
#pragma alloc_text(PAGE, TestUtilpMiPurgeTransitionList)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS TestUtilPageOut() {
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Paging out. Could be slow.");
  auto status = TestUtilpMmEmptyAllWorkingSets();
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = TestUtilpMmFlushAllPages();
  if (!NT_SUCCESS(status)) {
    return status;
  }
  return TestUtilpMiPurgeTransitionList();
}

_Use_decl_annotations_ static NTSTATUS TestUtilpMiPurgeTransitionList() {
  PAGED_CODE();

  auto status = TestUtilpExecuteSystemMemoryListOperation(4);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  return TestUtilpExecuteSystemMemoryListOperation(5);
}

_Use_decl_annotations_ static NTSTATUS TestUtilpMmFlushAllPages() {
  PAGED_CODE();

  return TestUtilpExecuteSystemMemoryListOperation(3);
}

_Use_decl_annotations_ static NTSTATUS TestUtilpMmEmptyAllWorkingSets() {
  PAGED_CODE();

  return TestUtilpExecuteSystemMemoryListOperation(2);
}

_Use_decl_annotations_ static NTSTATUS
TestUtilpExecuteSystemMemoryListOperation(ULONG operation_number) {
  PAGED_CODE();

  typedef NTSTATUS(NTAPI * NtSetSystemInformationType)(
      _In_ ULONG /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
      _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength);

  static const ULONG SystemMemoryListInformation = 0x50;

  static const auto NtSetSystemInformationPtr =
      reinterpret_cast<NtSetSystemInformationType>(
          UtilGetSystemProcAddress(L"ZwSetSystemInformation"));
  NT_ASSERT(NtSetSystemInformationPtr);

  return NtSetSystemInformationPtr(SystemMemoryListInformation,
                                   &operation_number, sizeof(operation_number));
}

}  // extern "C"
