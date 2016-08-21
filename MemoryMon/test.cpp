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

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe1(
    _Inout_ UCHAR* pagable_test_page);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe2();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS TestpForEachDriver(
    _In_ bool (*callback)(const RTL_PROCESS_MODULE_INFORMATION&, void*),
    _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool TestpForEachDriverCallback(
    _In_ const RTL_PROCESS_MODULE_INFORMATION& module, _In_opt_ void* context);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, TestRwe)
#pragma alloc_text(INIT, TestpForEachDriver)
#pragma alloc_text(INIT, TestpForEachDriverCallback)

// Locate TestpRwe1 on a NonPagable code section outside of the .text section
// and TestpRwe2 on Pagable code section outside of the PAGE section. Note that
// MSVC seems to make a section pagable when a section name starts with PAGE and
// any other code sections are set as NonPagable as default.
#pragma alloc_text(textTEST, TestpRwe1)
#pragma alloc_text(PAGETEST, TestpRwe2)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Runs a set of tests for MemoryMonRWE
_Use_decl_annotations_ void TestRwe() {
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  if (MemTraceIsEnabled()) {
    TestpForEachDriver(TestpForEachDriverCallback, nullptr);
    RweApplyRanges();
    HYPERPLATFORM_LOG_INFO("Enabled.");
    return;
  }

  // Set TestpRwe1() and TestpRwe2() as source ranges. Those functions are
  // located at the page boundaries: xxxxTEST and PAGETEST sections
  // respectively.
  //
  // It is safe to set an entire pages as source ranges as those sections do not
  // contain any other contents.
  RweAddSrcRange(&TestpRwe1, PAGE_SIZE);
  RweAddSrcRange(&TestpRwe2, PAGE_SIZE);

  // Set DbgPrintEx() and KdDebuggerNotPresent as dest ranges so that access to
  // those from TestpRwe1() and TestpRwe2() can be monitored. It is not fully
  // analyzed and tested what happens if outside of those ranges but still
  // inside the page is accessed.
  RweAddDstRange(&DbgPrintEx, 1);
  RweAddDstRange(KdDebuggerNotPresent, 1);

  // Set a pageable test page as a dest range. Touch it so that the VA is backed
  // by PA for testing purpose.
  const auto pagable_test_page = reinterpret_cast<UCHAR*>(
      ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));
  NT_ASSERT(pagable_test_page);
  RtlZeroMemory(pagable_test_page, PAGE_SIZE);
  RweAddDstRange(pagable_test_page, PAGE_SIZE);

  // Reflect all range data to EPT
  RweApplyRanges();

  // Run the first test. All of source and dest ranges will be backed by PA now.
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(pagable_test_page);
  TestpRwe2();
  HYPERPLATFORM_LOG_DEBUG("pagable_test_page[0]: %02x", *pagable_test_page);

  // Forcibly page out memory as much as possible.
  NT_VERIFY(NT_SUCCESS(TestUtilPageOut()));

  // Run the second test. Some of ranges will not be backed by PA until they
  // are accessed by test code.
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(pagable_test_page);
  TestpRwe2();
  HYPERPLATFORM_LOG_DEBUG("pagable_test_page[0]: %02x", *pagable_test_page);

  // Test finished
  HYPERPLATFORM_COMMON_DBG_BREAK();
  ExFreePoolWithTag(pagable_test_page, kHyperPlatformCommonPoolTag);
}

// A test function located in a non-pagable page
_Use_decl_annotations_ static void TestpRwe1(UCHAR* pagable_test_page) {
  const auto not_present = *KdDebuggerNotPresent;

  // Read inside one of dest ranges
  if (!not_present) {
    // Execute inside one of dest ranges. It is likely that not_present is now
    // stored in a register and access to it is not reported here.
    HYPERPLATFORM_LOG_INFO("Hello from %s (*KdDebuggerNotPresent = %d)",
                           __FUNCTION__, not_present);
  }

  // Write inside one of dest ranges
  *KdDebuggerNotPresent = 0xff;
  *KdDebuggerNotPresent = not_present;

// Read from and write to the pagable test page. This address may or may not
// be backed by PA before this write operation.
#if defined(_AMD64_)
  const auto current_value = *reinterpret_cast<ULONG64*>(pagable_test_page);
  __stosq(reinterpret_cast<ULONG64*>(pagable_test_page),
          current_value + 0x1111111111111111, PAGE_SIZE / sizeof(ULONG64));
#else
  const auto current_value = *reinterpret_cast<ULONG*>(pagable_test_page);
  __stosd(reinterpret_cast<ULONG*>(pagable_test_page),
          current_value + 0x11111111, PAGE_SIZE / sizeof(ULONG));
#endif
}

// A test function located in a pageable page
_Use_decl_annotations_ static void TestpRwe2() {
  PAGED_CODE();

  // Execute inside one of dest ranges
  HYPERPLATFORM_LOG_INFO("Hello from %s", __FUNCTION__);
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
  if (strcmp(name, "storahci.sys") == 0) {
    RweAddSrcRange(module.ImageBase, module.ImageSize);
    return false;   // stop enumeration
  }
  return true;
}

}  // extern "C"
