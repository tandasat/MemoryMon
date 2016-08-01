// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements page-fault functions.

#include "pagefault.h"
#include "scoped_lock.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <algorithm>

#pragma section(".asm", read, execute)

struct FaultMap {
  PETHREAD thread;
  void* guest_ip;
};

class MyMap {
 public:
  MyMap() { KeInitializeSpinLock(&spin_lock_); }

  void push(PETHREAD thread, void* guest_ip) {
    ScopedLock lock(&spin_lock_);
    pfp_map_.push_back(FaultMap{thread, guest_ip});
  }

  bool has(PETHREAD thread) const {
    ScopedLock lock(&spin_lock_);
    const auto position = std::find_if(
        pfp_map_.begin(), pfp_map_.end(),
        [thread](const auto& elem) { return elem.thread == thread; });
    return (position != pfp_map_.end());
  }

  void* pop(PETHREAD thread) {
    ScopedLock lock(&spin_lock_);
    const auto position = std::find_if(
        pfp_map_.begin(), pfp_map_.end(),
        [thread](const auto& elem) { return elem.thread == thread; });
    if (position == pfp_map_.end()) {
      return nullptr;
    }
    const auto guest_ip = position->guest_ip;
    pfp_map_.erase(position);
    return guest_ip;
  }

 private:
  std::vector<FaultMap> pfp_map_;
  mutable KSPIN_LOCK spin_lock_;
} g_pfp_map;

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

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

bool PageFaultHanlePageFault(void* guest_ip) {
  if (guest_ip < MmSystemRangeStart) {
    return false;
  }
  if (g_pfp_map.has(PsGetCurrentThread())) {
    return false;
  }

  UtilVmWrite(VmcsField::kGuestRip,
              reinterpret_cast<ULONG_PTR>(&kPageFaultpBreakPoint));
  g_pfp_map.push(PsGetCurrentThread(), guest_ip);
  return true;
}

bool PageFaultHandleBreakpoint(void* guest_ip) {
  if (guest_ip != kPageFaultpBreakPoint) {
    return false;
  }

  const auto last_ip = g_pfp_map.pop(PsGetCurrentThread());
  NT_ASSERT(last_ip);
  UtilVmWrite(VmcsField::kGuestRip, reinterpret_cast<ULONG_PTR>(last_ip));
  return true;
}

}  // extern "C"
