// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements page-fault functions.

#include "page_fault.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "page_fault_record.h"

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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PageFaultRecord g_pfp_record;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ bool PageFaultHanlePageFault(void* guest_ip) {
  if (guest_ip < MmSystemRangeStart) {
    return false;
  }
  if (g_pfp_record.has(PsGetCurrentThread())) {
    return false;
  }

  UtilVmWrite(VmcsField::kGuestRip,
              reinterpret_cast<ULONG_PTR>(&kPageFaultpBreakPoint));
  g_pfp_record.push(PsGetCurrentThread(), guest_ip);
  return true;
}

_Use_decl_annotations_ bool PageFaultHandleBreakpoint(void* guest_ip) {
  if (guest_ip != kPageFaultpBreakPoint) {
    return false;
  }

  const auto last_ip = g_pfp_record.pop(PsGetCurrentThread());
  NT_ASSERT(last_ip);
  UtilVmWrite(VmcsField::kGuestRip, reinterpret_cast<ULONG_PTR>(last_ip));
  return true;
}

}  // extern "C"
