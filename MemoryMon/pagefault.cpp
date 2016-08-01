// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements page-fault functions.

#include "pagefault.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"

#pragma section(".asm", read, execute)

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

__declspec(allocate(".asm")) static const UCHAR kPageFaultpBreakPoint[] = {
    0xcc};

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct PageFaultData {
  void* last_ip;

  PageFaultData() : last_ip(nullptr) {}
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PageFaultAllocData)
#pragma alloc_text(PAGE, PageFaultFreeData)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

PageFaultData* PageFaultAllocData() {
  PAGED_CODE();
  return new PageFaultData;
}

void PageFaultFreeData(PageFaultData* page_fault_data) {
  PAGED_CODE();
  delete page_fault_data;
}

bool PageFaultHanlePageFault(PageFaultData* page_fault_data, void* guest_ip) {
  if (guest_ip < MmSystemRangeStart) {
    return false;
  }
  if (page_fault_data->last_ip) {
    return false;
  }

  HYPERPLATFORM_LOG_DEBUG_SAFE("#PF %p", guest_ip);
  UtilVmWrite(VmcsField::kGuestRip,
              reinterpret_cast<ULONG_PTR>(&kPageFaultpBreakPoint));
  NT_ASSERT(!page_fault_data->last_ip);
  page_fault_data->last_ip = guest_ip;
  return true;
}

bool PageFaultHandleBreakpoint(PageFaultData* page_fault_data, void* guest_ip) {
  if (guest_ip != kPageFaultpBreakPoint) {
    return false;
  }

  HYPERPLATFORM_LOG_DEBUG_SAFE("#BP %p", page_fault_data->last_ip);
  NT_ASSERT(page_fault_data->last_ip);

  UtilVmWrite(VmcsField::kGuestRip,
              reinterpret_cast<ULONG_PTR>(page_fault_data->last_ip));
  page_fault_data->last_ip = nullptr;
  return true;
}

}  // extern "C"
