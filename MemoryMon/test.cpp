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
#include "test_util.h"

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

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe1(_Inout_ UCHAR* ptr);

_IRQL_requires_max_(PASSIVE_LEVEL) static void TestpRwe2();

// Locate TestpRwe1 on a NonPagable code section outside of the .text section
// and TestpRwe2 on Pagable code section outside of the PAGE section. Note that
// MSVC seems to make a section pagable when a section name starts with PAGE and
// any other code sections are set as NonPagable as default.
#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, TestRwe)
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

_Use_decl_annotations_ void TestRwe() {
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  RweAddSrcRange(&TestpRwe1, PAGE_SIZE);
  RweAddSrcRange(&TestpRwe2, PAGE_SIZE);

  RweAddDstRange(&DbgPrintEx, 1);
  RweAddDstRange(KdDebuggerNotPresent, 1);

  const auto stuff = reinterpret_cast<UCHAR*>(
      ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));

  NT_ASSERT(stuff);
  NT_VERIFY(TestUtilPageOut());
  RtlZeroMemory(stuff, PAGE_SIZE);
  RweAddDstRange(stuff, PAGE_SIZE);

  RweApplyRanges();

  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe1(stuff);
  HYPERPLATFORM_LOG_DEBUG("Byte = %02x", *stuff);

  NT_VERIFY(TestUtilPageOut());
  HYPERPLATFORM_COMMON_DBG_BREAK();
  TestpRwe2();
  TestpRwe1(stuff);
  HYPERPLATFORM_LOG_DEBUG("Byte = %02x", *stuff);
  HYPERPLATFORM_COMMON_DBG_BREAK();

  ExFreePoolWithTag(stuff, kHyperPlatformCommonPoolTag);
}

// The function 'TestpRwe1' has PAGED_CODE or PAGED_CODE_LOCKED but is not
// declared to be in a paged segment.
#pragma prefast(suppress : 28172)
_Use_decl_annotations_ static void TestpRwe1(UCHAR* ptr) {
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
  const auto now = *ptr;
  *ptr = now + 1;
}

_Use_decl_annotations_ static void TestpRwe2() {
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO_SAFE("Hello from %s", __FUNCTION__);
}

}  // extern "C"
