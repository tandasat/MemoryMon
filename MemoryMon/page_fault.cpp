// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements page-fault functions.

#include "page_fault.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "PageFaultRecord.h"

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

// Locate 0xcc on a discrete section so that it cannot be affected by any src
// or dest ranges used in tests. This code can be located on .text when we made
// sure any test code did not affect to kPfpBreakPoint. For the same
// reason, nt!DbgBreakPoint is not used at this moment.
//
// Note that this handler cannot be used for #PF occurred in ring-3 context, as
// the Requested Privilege Level of this code is 0, obviously.
__declspec(allocate(".asm")) static const UCHAR kPfpBreakPoint[] = {0xcc};

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, PfStopPageFaultHandling)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PageFaultRecord g_pfp_record;
static bool g_pfp_stop_handling;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Change guest's IP to kPfpBreakPoint up on #PF on kernel address space
// so that #BP VM-exit occurs on completion of #PF handler
_Use_decl_annotations_ bool PfHandlePageFault(void* guest_ip) {
  if (g_pfp_stop_handling) {
    return false;
  }
  if (g_pfp_record.has(PsGetCurrentThread())) {
    return false;
  }

  UtilVmWrite(VmcsField::kGuestRip,
              reinterpret_cast<ULONG_PTR>(&kPfpBreakPoint));
  g_pfp_record.push(PsGetCurrentThread(), guest_ip);
  return true;
}

// Checks whether the #BP occurred up on completion of #PF handler, and so,
// restores an original IP to continue guest execution as it should be
_Use_decl_annotations_ bool PfHandleBreakpoint(void* guest_ip) {
  if (guest_ip != kPfpBreakPoint) {
    return false;
  }

  const auto last_ip = g_pfp_record.pop(PsGetCurrentThread());
  NT_ASSERT(last_ip);
  UtilVmWrite(VmcsField::kGuestRip, reinterpret_cast<ULONG_PTR>(last_ip));
  return true;
}

//
_Use_decl_annotations_ void PfStopPageFaultHandling() {
  PAGED_CODE();

  g_pfp_stop_handling = true;
  UtilSleep(1000);
}

}  // extern "C"
