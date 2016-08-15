// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Implements extended code as the MemoryMon

#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "memorymon.h"
#include <intrin.h>
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif  // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "../HyperPlatform/HyperPlatform/performance.h"

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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, MmonInitialization)
#pragma alloc_text(PAGE, MmonTermination)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes MemoryMon
_Use_decl_annotations_ NTSTATUS MmonInitialization() {
  PAGED_CODE();

  return STATUS_SUCCESS;
}

// Terminates MemoryMon
_Use_decl_annotations_ void MmonTermination() { PAGED_CODE(); }

}  // extern "C"
