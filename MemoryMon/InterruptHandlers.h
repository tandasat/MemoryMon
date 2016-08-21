// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to the InterruptHandlers class.

#ifndef MEMORYMON_INTERRUPTHANDLERS_H_
#define MEMORYMON_INTERRUPTHANDLERS_H_

#include <fltKernel.h>
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <array>

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

class InterruptHandlers {
 public:
  InterruptHandlers();

  bool has(void* addr) const;

 private:
  struct InterruptHandlerEntry {
    void* handler;
    mutable volatile LONG64 hit_counter;
  };

  std::array<InterruptHandlerEntry, 0xff> handlers;
};

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

#endif MEMORYMON_INTERRUPTHANDLERS_H_
