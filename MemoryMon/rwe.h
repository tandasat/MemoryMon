// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to RWE functions.

#ifndef MEMORYMON_RWE_H_
#define MEMORYMON_RWE_H_

#include <fltKernel.h>
#include "../HyperPlatform/HyperPlatform/ia32_type.h"

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

struct ProcessorData;

struct RweData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) RweData* RweAllocData();

_IRQL_requires_max_(PASSIVE_LEVEL) void RweFreeData(_In_ RweData* rwe_data);

void RweAddSrcRange(_In_ void* address, _In_ SIZE_T size);

void RweAddDstRange(_In_ void* address, _In_ SIZE_T size);

bool RweIsInsideSrcRange(_In_ void* address);

bool RweIsInsideDstRange(_In_ void* address);

_IRQL_requires_max_(PASSIVE_LEVEL) void RweSetDefaultEptAttributes(
    _Inout_ ProcessorData* processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) void RweApplyRanges();

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleNewDeviceMemoryAccess(
    _In_ ULONG64 pa, _In_ void* va);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleEptViolation(
    _Inout_ ProcessorData* processor_data, _In_ void* guest_ip,
    _In_ void* fault_va, _In_ bool read_violation, _In_ bool write_violation,
    _In_ bool execute_violation);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleMonitorTrapFlag(
    _Inout_ ProcessorData* processor_data, _In_ GpRegisters* gp_regs);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweVmcallApplyRanges(
    _Inout_ ProcessorData* processor_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void RweHandleTlbFlush(
    _Inout_ ProcessorData* processor_data);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // MEMORYMON_RWE_H_
