// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares mem_trace functions.

#ifndef MEMORYMON_MEM_TRACE_H_
#define MEMORYMON_MEM_TRACE_H_

#include <fltKernel.h>

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

#if defined(_AMD64_)
using GpRegisters = struct GpRegistersX64;
#else
using GpRegisters = struct GpRegistersX86;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

bool MemTraceIsEnabled();

bool MemTraceIsTargetSrcAddress(_In_ const char* name);

bool MemTraceIsTargetDstAddress(_In_ ULONG64 pa);

_Success_(return ) bool MemTraceHandleReadWrite(_In_ void* guest_ip,
                                                _Inout_ GpRegisters* gp_regs,
                                                _In_ bool is_write);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif MEMORYMON_MEM_TRACE_H_
