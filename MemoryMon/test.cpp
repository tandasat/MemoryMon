// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "test.h"
#include <intrin.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "rwe.h"
#include "test_util.h"
#include "mem_trace.h"

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

struct RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS TestpForEachDriver(
    _In_ bool (*callback)(const RTL_PROCESS_MODULE_INFORMATION&, void*),
    _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TestpForEachDriverCallback(
    _In_ const RTL_PROCESS_MODULE_INFORMATION& module, _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TestpForEachDriverCallbackForNgs(
    _In_ const RTL_PROCESS_MODULE_INFORMATION& module, _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING full_image_name, _In_ HANDLE process_id,
    _In_ PIMAGE_INFO image_info);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, TestInitialization)
#pragma alloc_text(INIT, TestRwe)
#pragma alloc_text(INIT, TestpForEachDriver)
#pragma alloc_text(INIT, TestpForEachDriverCallback)
#pragma alloc_text(INIT, TestpForEachDriverCallbackForNgs)
#pragma alloc_text(PAGE, TestTermination)
#pragma alloc_text(PAGE, TestpLoadImageNotifyRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static UNICODE_STRING kTestpTargetDriverExpressions[] = {
    RTL_CONSTANT_STRING(L"*\\NGS*.SYS"),
};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS TestInitialization() {
  PAGED_CODE();

  auto status = PsSetLoadImageNotifyRoutine(TestpLoadImageNotifyRoutine);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return status;
}
_Use_decl_annotations_ void TestTermination() {
  PAGED_CODE();

  PsRemoveLoadImageNotifyRoutine(TestpLoadImageNotifyRoutine);
}

// Runs a set of tests for MemoryMonRWE
_Use_decl_annotations_ void TestRwe() {
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  if (MemTraceIsEnabled()) {
    TestpForEachDriver(TestpForEachDriverCallback, nullptr);
    RweApplyRanges();
    HYPERPLATFORM_COMMON_DBG_BREAK();
    HYPERPLATFORM_LOG_INFO("Enabled.");
    return;
  }

  TestpForEachDriver(TestpForEachDriverCallbackForNgs, nullptr);

  // Protect HalDispatchTable[1] from being written
  HYPERPLATFORM_LOG_INFO("Write Protect: %p : hal!HalDispatchTable[1]",
                         &HalQuerySystemInformation);
  RweAddDstRange(&HalQuerySystemInformation, sizeof(void*));

  // Reflect all range data to EPT
  RweApplyRanges();
}

// Executes callback for each driver currently loaded
_Use_decl_annotations_ static NTSTATUS TestpForEachDriver(
    bool (*callback)(const RTL_PROCESS_MODULE_INFORMATION&, void*),
    void* context) {
  PAGED_CODE();

  // For ZwQuerySystemInformation
  enum SystemInformationClass {
    SystemModuleInformation = 11,
  };

  NTSTATUS NTAPI ZwQuerySystemInformation(
      _In_ SystemInformationClass SystemInformationClass,
      _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
      _Out_opt_ PULONG ReturnLength);

  struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
  };

  // Get a necessary size of buffer
  ULONG_PTR dummy = 0;
  ULONG return_length = 0;
  auto status = ZwQuerySystemInformation(SystemModuleInformation, &dummy,
                                         sizeof(dummy), &return_length);
  if (NT_SUCCESS(status) || return_length <= sizeof(dummy)) {
    return status;
  }

  // Allocate s bit larger buffer to handle new processes in case
  const ULONG allocation_size =
      return_length + sizeof(RTL_PROCESS_MODULE_INFORMATION) * 3;
  const auto system_info =
      reinterpret_cast<RTL_PROCESS_MODULES*>(ExAllocatePoolWithTag(
          PagedPool, allocation_size, kHyperPlatformCommonPoolTag));
  if (!system_info) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  status = ZwQuerySystemInformation(SystemModuleInformation, system_info,
                                    allocation_size, &return_length);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
    return status;
  }

  // For each process
  for (auto i = 0ul; i < system_info->NumberOfModules; ++i) {
    const auto& module = system_info->Modules[i];
    if (!callback(module, context)) {
      break;
    }
  }

  ExFreePoolWithTag(system_info, kHyperPlatformCommonPoolTag);
  return status;
}

// Sets certain drivers as source ranges
_Use_decl_annotations_ static bool TestpForEachDriverCallback(
    const RTL_PROCESS_MODULE_INFORMATION& module, void* context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(context);

  HYPERPLATFORM_LOG_DEBUG(
      "%p - %p: %s", module.ImageBase,
      reinterpret_cast<ULONG_PTR>(module.ImageBase) + module.ImageSize,
      module.FullPathName);

  const auto name = reinterpret_cast<const char*>(module.FullPathName) +
                    module.OffsetToFileName;
  if (MemTraceIsTargetSrcAddress(name)) {
    RweAddSrcRange(module.ImageBase, module.ImageSize);
  }
  return true;
}

_Use_decl_annotations_ static bool TestpForEachDriverCallbackForNgs(
    const RTL_PROCESS_MODULE_INFORMATION& module, void* context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(context);

  ANSI_STRING fullpath_A = {};
  RtlInitAnsiString(&fullpath_A,
                    reinterpret_cast<const char*>(module.FullPathName));
  UNICODE_STRING fullpath_U = {};
  auto status = RtlAnsiStringToUnicodeString(&fullpath_U, &fullpath_A, TRUE);
  if (!NT_SUCCESS(status)) {
    return true;
  }
  for (auto& expression : kTestpTargetDriverExpressions) {
    if (!FsRtlIsNameInExpression(&expression, &fullpath_U, TRUE, nullptr)) {
      continue;
    }

    HYPERPLATFORM_LOG_DEBUG(
        "Untrusted driver is detected. Add the range it for trace.");
    HYPERPLATFORM_LOG_DEBUG("Name: %wZ", &fullpath_U);
    RweAddSrcRange(module.ImageBase, module.ImageSize);
    break;
  }
  RtlFreeUnicodeString(&fullpath_U);
  return true;
}

_Use_decl_annotations_ static void TestpLoadImageNotifyRoutine(
    PUNICODE_STRING full_image_name,
    HANDLE process_id,  // pid into which image is being mapped
    PIMAGE_INFO image_info) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(process_id);

  if (!full_image_name || !image_info->SystemModeImage) {
    return;
  }

  HYPERPLATFORM_LOG_DEBUG("New driver: %wZ", full_image_name);

  for (auto& expression : kTestpTargetDriverExpressions) {
    if (!FsRtlIsNameInExpression(&expression, full_image_name, TRUE, nullptr)) {
      continue;
    }

    HYPERPLATFORM_LOG_DEBUG(
        "Untrusted driver is detected. Add the range it for trace.");
    HYPERPLATFORM_LOG_DEBUG("Name: %wZ", full_image_name);
    RweAddSrcRange(image_info->ImageBase, image_info->ImageSize);
    RweApplyRanges();
    break;
  }
}

}  // extern "C"
