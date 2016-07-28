// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "test.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "rwe.h"

//#pragma section("SRC", read, execute)

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

static void TestpRwe1(UCHAR* ptr);

static void TestpRwe2();

// Locate TestpRwe1 on a NonPagable code section outside of the .text section
// and TestpRwe2 on Pagable code section outside of the PAGE section. Note that
// MSVC seems to make a section pagable when a section name starts with PAGE and
// any other code sections are set as NonPagable as default.
#if defined(ALLOC_PRAGMA)
#pragma alloc_text(____TEST, TestpRwe1)
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

//
// Support functions
//

static bool TestpExecuteSystemMemoryListOperation(
    ULONG memory_operation_number) {
  PAGED_CODE();

  typedef NTSTATUS(NTAPI * NtSetSystemInformationType)(
      _In_ ULONG /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
      _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength);

  static const ULONG SystemMemoryListInformation = 0x50;

  static const auto NtSetSystemInformationPtr =
      reinterpret_cast<NtSetSystemInformationType>(
          UtilGetSystemProcAddress(L"ZwSetSystemInformation"));
  NT_ASSERT(NtSetSystemInformationPtr);

  auto status = NtSetSystemInformationPtr(SystemMemoryListInformation,
                                          &memory_operation_number,
                                          sizeof(memory_operation_number));
  return NT_SUCCESS(status);
}

static bool TestpMmEmptyAllWorkingSets() {
  PAGED_CODE();

  return TestpExecuteSystemMemoryListOperation(2);
}

static bool TestpMmFlushAllPages() {
  PAGED_CODE();

  return TestpExecuteSystemMemoryListOperation(3);
}

static bool TestpMiPurgeTransitionList() {
  PAGED_CODE();

  return (TestpExecuteSystemMemoryListOperation(4) &&
          TestpExecuteSystemMemoryListOperation(5));
}

static bool TestpPageOut() {
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Paging out. Could be slow.");
  if (!TestpMmEmptyAllWorkingSets()) {
    return false;
  }
  if (!TestpMmFlushAllPages()) {
    return false;
  }
  if (!TestpMiPurgeTransitionList()) {
    return false;
  }
  return true;
}

//
// Main test code
//

void TestRwe() {
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  RweAddSrcRange((ULONG_PTR)&TestpRwe1, PAGE_SIZE);
  RweAddSrcRange((ULONG_PTR)&TestpRwe2, PAGE_SIZE);

  RweAddDstRange((ULONG_PTR)&DbgPrintEx, 1);
  RweAddDstRange((ULONG_PTR)KdDebuggerNotPresent, 1);

  const auto stuff = reinterpret_cast<UCHAR*>(
      ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));

  NT_ASSERT(stuff);
  NT_VERIFY(TestpPageOut());
  RtlZeroMemory(stuff, PAGE_SIZE);
  RweAddDstRange((ULONG_PTR)stuff, PAGE_SIZE);

  RweApplyRanges();

  TestpRwe1(nullptr);
  HYPERPLATFORM_LOG_DEBUG("Cool");
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(stuff);
  HYPERPLATFORM_LOG_DEBUG("Byte = %02x", *stuff);

  NT_VERIFY(TestpPageOut());
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe2();
  TestpRwe1(stuff);
  HYPERPLATFORM_LOG_DEBUG("Byte = %02x", *stuff);
  HYPERPLATFORM_COMMON_DBG_BREAK();

  ExFreePoolWithTag(stuff, kHyperPlatformCommonPoolTag);
}

static void TestpRwe1(UCHAR* ptr) {
  PAGED_CODE();

  const auto not_present = *KdDebuggerNotPresent;
  if (not_present) {
    NOTHING;
  } else {
    HYPERPLATFORM_LOG_INFO_SAFE("Hello from %s (*KdDebuggerNotPresent = %d)",
                                __FUNCTION__, not_present);
  }
  *KdDebuggerNotPresent = 0xff;
  *KdDebuggerNotPresent = not_present;
  //__debugbreak();
  if (ptr) {
    const auto now = *ptr;
    *ptr = now + 1;
  }
}

static void TestpRwe2() {
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO_SAFE("Hello from %s", __FUNCTION__);
}

}  // extern "C"
