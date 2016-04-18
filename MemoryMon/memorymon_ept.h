// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Declares EPT related parts of MemoryMon code

#ifndef MEMORYMON_MEMORYMON_EPT_H_
#define MEMORYMON_MEMORYMON_EPT_H_

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

struct MmonEptData;
union EptCommonEntry;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL)
    MmonEptData *MmoneptInitialization(_In_ EptData *ept_data);

void MmoneptTermination(_In_ MmonEptData *mmon_ept_data);

void MmoneptResetDisabledEntries(_In_ MmonEptData *mmon_ept_data);

void MmoneptHandleDodgyRegionExecution(_In_ MmonEptData *mmon_ept_data,
                                       _In_ EptCommonEntry *ept_pt_entry,
                                       _In_ ULONG64 fault_pa,
                                       _In_ void *fault_va);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // MEMORYMON_MEMORYMON_EPT_H_
