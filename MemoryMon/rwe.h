// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to RWE functions.

#ifndef MEMORYMON_RWE_H_
#define MEMORYMON_RWE_H_

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

struct ProcessorData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

void RwepTestCode();
NTSTATUS RweInitialization();
void RweTermination();

void RweAddSrcRange(ULONG_PTR address, SIZE_T size);
void RweAddDstRange(ULONG_PTR address, SIZE_T size);
bool RweIsInsideSrcRange(ULONG_PTR address);
bool RweIsInsideDstRange(ULONG_PTR address);

void RweHandleEptViolation(ProcessorData* processor_data, ULONG_PTR guest_ip,
                           ULONG_PTR fault_va, bool read_violation,
                           bool write_violation, bool execute_violation);
void RweHandleMonitorTrapFlag();

void RweApplyRanges();
void RweVmcallApplyRanges(ProcessorData* processor_data);

void RweSetDefaultEptAttributes(ProcessorData* processor_data);

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
