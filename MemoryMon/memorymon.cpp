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

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    MmonpInitializeMmPfnDatabase();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, MmonInitialization)
#pragma alloc_text(PAGE, MmonTermination)
#pragma alloc_text(INIT, MmonpInitializeMmPfnDatabase)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static void *g_mmonp_MmPfnDatabase;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes MemoryMon
_Use_decl_annotations_ NTSTATUS MmonInitialization() {
  PAGED_CODE();

  auto status = MmonpInitializeMmPfnDatabase();
  HYPERPLATFORM_LOG_DEBUG("MmPfnDatabase = %p", g_mmonp_MmPfnDatabase);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  return STATUS_SUCCESS;
}

// Terminates MemoryMon
_Use_decl_annotations_ void MmonTermination() { PAGED_CODE(); }

// Locate MmPfnDatabase
_Use_decl_annotations_ static NTSTATUS MmonpInitializeMmPfnDatabase() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Set appropriate patterns and based on an OS version
  const void *pattern = nullptr;
  SIZE_T pattern_size = 0;
  bool hard_coded = false;

  if (IsX64()) {
    // Win 10 build 14316 is the first version implements randomized page tables
    if (os_version.dwMajorVersion < 10 || os_version.dwBuildNumber < 14316) {
      // PFN database is at the constant location on older x64 Windows
      g_mmonp_MmPfnDatabase = reinterpret_cast<void *>(0xfffffa8000000000);
      return STATUS_SUCCESS;
    }

    // Windows 10 x64 Build 14332+
    static const UCHAR kPatternWin10x64[] = {
        0x48, 0x8B, 0xC1,        // mov     rax, rcx
        0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
        0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
        0x48, 0x03, 0xD2,        // add     rdx, rdx
        0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
    };
    pattern = kPatternWin10x64;
    pattern_size = sizeof(kPatternWin10x64);
    hard_coded = true;

  } else {
    // x86
    if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 1) {
      // Windows 7 (No PAE)
      static const UCHAR kPatternWin7[] = {
          0x6B, 0xC0, 0x18,  // imul    eax, 18h
          0x8B, 0x0D,        // mov     ecx, ds:_MmPfnDatabase
      };
      // Windows 7 (PAE)
      static const UCHAR kPatternWin7Pae[] = {
          0x6B, 0xC0, 0x1C,  // imul    eax, 1Ch
          0x8B, 0x0D,        // mov     ecx, ds:_MmPfnDatabase
      };

      if (UtilIsX86Pae()) {
        pattern = kPatternWin7Pae;
        pattern_size = sizeof(kPatternWin7Pae);
      } else {
        pattern = kPatternWin7;
        pattern_size = sizeof(kPatternWin7);
      }

    } else if ((os_version.dwMajorVersion == 6 &&
                os_version.dwMinorVersion == 3) ||
               (os_version.dwMajorVersion == 10 &&
                os_version.dwMinorVersion == 0)) {
      // Windows 8.1 and 10
      static const UCHAR kPatternWin81And10[] = {
          0xC1, 0xF8, 0x0C,  // sar     eax, 0Ch
          0xA1,              // mov     eax, ds:_MmPfnDatabase
      };
      pattern = kPatternWin81And10;
      pattern_size = sizeof(kPatternWin81And10);

    } else {
      // Unknown x86 OS version
      return STATUS_UNSUCCESSFUL;
    }
  }

  // Search the pattern
  const auto p_MmGetVirtualForPhysical = reinterpret_cast<UCHAR *>(
      UtilGetSystemProcAddress(L"MmGetVirtualForPhysical"));
  if (!p_MmGetVirtualForPhysical) {
    return STATUS_PROCEDURE_NOT_FOUND;
  }
  auto found = reinterpret_cast<UCHAR *>(
      UtilMemMem(p_MmGetVirtualForPhysical, 0x20, pattern, pattern_size));
  if (!found) {
    return STATUS_PROCEDURE_NOT_FOUND;
  }

  // Get an address of PFN database
  found += pattern_size;
  if (hard_coded) {
    HYPERPLATFORM_LOG_DEBUG("Found a hard coded PFN database address at %p",
                            found);
    g_mmonp_MmPfnDatabase = *reinterpret_cast<void **>(found);
  } else {
    HYPERPLATFORM_LOG_DEBUG("Found a reference to MmPfnDatabase at %p", found);
    const auto mmpfn_address = *reinterpret_cast<ULONG_PTR *>(found);
    g_mmonp_MmPfnDatabase = *reinterpret_cast<void **>(mmpfn_address);
  }

  // On Windows 10 RS, a value has 0x8. Delete it.
  g_mmonp_MmPfnDatabase = PAGE_ALIGN(g_mmonp_MmPfnDatabase);
  return STATUS_SUCCESS;
}

// Returns the MmPfnDatabase
/*_Use_decl_annotations_*/ void *MmonGetPfnDatabase() {
  return g_mmonp_MmPfnDatabase;
}

}  // extern "C"
