// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements the InterruptHandlers class.

#include "InterruptHandlers.h"
#include "../../HyperPlatform/HyperPlatform/ia32_type.h"

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

// dt nt!_kIDTENTRY64
struct IDTENTRY64 {
  USHORT OffsetLow;
  USHORT Selector;
  union {
    USHORT Access;
    struct {
      USHORT IstIndex : 3;
      USHORT Reserved0 : 5;
      USHORT Type : 5;
      USHORT Dpl : 2;
      USHORT Present : 1;
    } AccessField;
  };
  USHORT OffsetMiddle;
  ULONG OffsetHigh;
  ULONG Reserved1;
};
static_assert(sizeof(IDTENTRY64) == 0x10, "Size check");

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

InterruptHandlers::InterruptHandlers() {
  Idtr idtr = {};
  __sidt(&idtr);

  const auto entries = reinterpret_cast<IDTENTRY64*>(idtr.base);
  for (auto i = 0ul; i < handlers.size(); ++i) {
// warning C6011: dereferencing NULL pointer. FP due to unannotated __sidt
#pragma prefast(suppress : __WARNING_DEREF_NULL_PTR)
    const auto high = static_cast<ULONG_PTR>(entries[i].OffsetHigh) << 32;
    const auto middle = static_cast<ULONG_PTR>(entries[i].OffsetMiddle) << 16;
    const auto low = static_cast<ULONG_PTR>(entries[i].OffsetLow);
    const auto handler = (high | middle | low);

    handlers[i].handler = reinterpret_cast<void*>(handler);
  }
}

bool InterruptHandlers::has(void* addr) const {
  for (auto& handler : handlers) {
    if (handler.handler == addr) {
      InterlockedIncrement64(&handler.hit_counter);
      return true;
    }
  }
  return false;
}
