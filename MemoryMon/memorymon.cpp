// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements extended code as the MemoryMon.
//
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "memorymon.h"
#include <intrin.h>
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "../HyperPlatform/HyperPlatform/performance.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Use RtlPcToFileHeader if available. Using the API causes a broken font bug
// on the 64 bit Windows 10 and should be avoided. This flag exist for only
// futher investigation.
static const auto kMmonpUseRtlPcToFileHeader = false;

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

using RtlPcToFileHeaderType = decltype(RtlPcToFileHeader);

//
// dt nt!_LDR_DATA_TABLE_ENTRY
//
struct LdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_initialization_order_links;
  void *dll_base;
  void *entry_point;
  ULONG size_of_image;
  UNICODE_STRING full_dll_name;
  // ...
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    MmonpInitializeRtlPcToFileHeader(_In_ PDRIVER_OBJECT driver_object);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    MmonpInitializeMmPfnDatabase();

_Success_(return != nullptr) static PVOID NTAPI
    MmonpUnsafePcToFileHeader(_In_ PVOID pc_value, _Out_ PVOID *base_of_image);

static void MmonpInvalidateInstructionCache(_In_ void *base_address,
                                            _In_ SIZE_T length);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, MmonInitialization)
#pragma alloc_text(PAGE, MmonTermination)
#pragma alloc_text(INIT, MmonpInitializeRtlPcToFileHeader)
#pragma alloc_text(INIT, MmonpInitializeMmPfnDatabase)
#pragma alloc_text(INIT, MmonExecuteDoggyRegion)
#pragma alloc_text(INIT, MmonpInvalidateInstructionCache)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//
static RtlPcToFileHeaderType *g_mmonp_RtlPcToFileHeader;
static void *g_mmonp_MmPfnDatabase;
static LIST_ENTRY *g_mmonp_PsLoadedModuleList;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes MemoryMon
_Use_decl_annotations_ NTSTATUS
MmonInitialization(PDRIVER_OBJECT driver_object) {
  PAGED_CODE();

  auto status = MmonpInitializeRtlPcToFileHeader(driver_object);
  HYPERPLATFORM_LOG_DEBUG("PcToFileHeader = %p", g_mmonp_RtlPcToFileHeader);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = MmonpInitializeMmPfnDatabase();
  HYPERPLATFORM_LOG_DEBUG("MmPfnDatabase = %p", g_mmonp_MmPfnDatabase);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  MmonExecuteDoggyRegion();
  return STATUS_SUCCESS;
}

// Terminates MemoryMon
_Use_decl_annotations_ void MmonTermination() { PAGED_CODE(); }

// Locates RtlPcToFileHeader
_Use_decl_annotations_ static NTSTATUS
MmonpInitializeRtlPcToFileHeader(PDRIVER_OBJECT driver_object) {
  PAGED_CODE();

  if (kMmonpUseRtlPcToFileHeader) {
    const auto p_RtlPcToFileHeader =
        UtilGetSystemProcAddress(L"RtlPcToFileHeader");
    if (p_RtlPcToFileHeader) {
      g_mmonp_RtlPcToFileHeader =
          reinterpret_cast<RtlPcToFileHeaderType *>(p_RtlPcToFileHeader);
      return STATUS_SUCCESS;
    }
  }

#pragma warning(push)
#pragma warning(disable : 28175)
  auto module =
      reinterpret_cast<LdrDataTableEntry *>(driver_object->DriverSection);
#pragma warning(pop)

  g_mmonp_PsLoadedModuleList = module->in_load_order_links.Flink;
  g_mmonp_RtlPcToFileHeader = MmonpUnsafePcToFileHeader;
  return STATUS_SUCCESS;
}

// Locate MmPfnDatabase
_Use_decl_annotations_ static NTSTATUS MmonpInitializeMmPfnDatabase() {
  PAGED_CODE();

  if (IsX64()) {
    g_mmonp_MmPfnDatabase = reinterpret_cast<void *>(0xfffffa8000000000);
  } else {
    const auto p_MmGetVirtualForPhysical = reinterpret_cast<UCHAR *>(
        UtilGetSystemProcAddress(L"MmGetVirtualForPhysical"));
    if (!p_MmGetVirtualForPhysical) {
      return STATUS_PROCEDURE_NOT_FOUND;
    }

    RTL_OSVERSIONINFOW os_version = {};
    auto status = RtlGetVersion(&os_version);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    if (os_version.dwMajorVersion == 6 && os_version.dwMinorVersion == 1) {
      // Windows 7 (No PAE)
      // 6B C0 18                          imul    eax, 18h
      // 8B 0D 14 28 56 00                 mov     ecx, ds:_MmPfnDatabase
      static const UCHAR kPatternWin7[] = {
          0x6B, 0xC0, 0x18, 0x8B, 0x0D,
      };
      // Windows 7 (PAE)
      // 6B C0 1C                          imul    eax, 1Ch
      // 8B 0D 14 28 56 00                 mov     ecx, ds:_MmPfnDatabase
      static const UCHAR kPatternWin7Pae[] = {
          0x6B, 0xC0, 0x1C, 0x8B, 0x0D,
      };
      const auto is_pae_enabled = Cr4{__readcr4()}.fields.pae;
      const auto pattern = (is_pae_enabled) ? kPatternWin7Pae : kPatternWin7;
      const auto size =
          (is_pae_enabled) ? sizeof(kPatternWin7Pae) : sizeof(kPatternWin7);
      auto found = reinterpret_cast<UCHAR *>(
          UtilMemMem(p_MmGetVirtualForPhysical, 0x20, pattern, size));
      if (found) {
        found += size;
        const auto address = *reinterpret_cast<ULONG_PTR *>(found);
        g_mmonp_MmPfnDatabase = *reinterpret_cast<void **>(address);
      }
    } else if ((os_version.dwMajorVersion == 6 &&
                os_version.dwMinorVersion == 3) ||
               (os_version.dwMajorVersion == 10 &&
                os_version.dwMinorVersion == 0)) {
      // Windows 8.1 and 10
      // C1 F8 0C                          sar     eax, 0Ch
      // A1 08 B7 62 00                    mov     eax, ds:_MmPfnDatabase
      static const UCHAR kPatternWin81And10[] = {
          0xC1, 0xF8, 0x0C, 0xA1,
      };
      auto found = reinterpret_cast<UCHAR *>(
          UtilMemMem(p_MmGetVirtualForPhysical, 0x20, kPatternWin81And10,
                     sizeof(kPatternWin81And10)));
      if (found) {
        found += sizeof(kPatternWin81And10);
        const auto address = *reinterpret_cast<ULONG_PTR *>(found);
        g_mmonp_MmPfnDatabase = *reinterpret_cast<void **>(address);
      }
    }
  }
  return (g_mmonp_MmPfnDatabase) ? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
}

// Returns the MmPfnDatabase
/*_Use_decl_annotations_*/ void *MmonGetPfnDatabase() {
  return g_mmonp_MmPfnDatabase;
}

// A wrapper of RtlPcToFileHeader
_Use_decl_annotations_ PVOID MmonPcToFileHeader(PVOID pc_value) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  void *base = nullptr;
  return g_mmonp_RtlPcToFileHeader(pc_value, &base);
}

// A fake RtlPcToFileHeader without accquireing PsLoadedModuleSpinLock. Thus, it
// is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.
_Use_decl_annotations_ static PVOID NTAPI
MmonpUnsafePcToFileHeader(PVOID pc_value, PVOID *base_of_image) {
  if (pc_value < MmSystemRangeStart) {
    return nullptr;
  }

  const auto head = g_mmonp_PsLoadedModuleList;
  for (auto current = head->Flink; current != head; current = current->Flink) {
    const auto module =
        CONTAINING_RECORD(current, LdrDataTableEntry, in_load_order_links);
    const auto driver_end = reinterpret_cast<void *>(
        reinterpret_cast<ULONG_PTR>(module->dll_base) + module->size_of_image);
    if (UtilIsInBounds(pc_value, module->dll_base, driver_end)) {
      *base_of_image = module->dll_base;
      return module->dll_base;
    }
  }
  return nullptr;
}

// Execute a non-image region as a test
_Use_decl_annotations_ void MmonExecuteDoggyRegion() {
  PAGED_CODE();

#pragma warning(push)
#pragma warning(disable : 30030)
  auto code = reinterpret_cast<UCHAR *>(ExAllocatePoolWithTag(
      NonPagedPoolExecute, PAGE_SIZE, kHyperPlatformCommonPoolTag));
#pragma warning(pop)

  if (!code) {
    return;
  }
  RtlZeroMemory(code, PAGE_SIZE);
  HYPERPLATFORM_LOG_DEBUG("PoolCode = %p, Pa = %016llx", code,
                          UtilPaFromVa(code));
  code[0] = 0x90; // nop
  code[1] = 0x90; // nop
  code[2] = 0xc3; // ret
  MmonpInvalidateInstructionCache(code, PAGE_SIZE);

  auto function = reinterpret_cast<void (*)(void)>(code);
  function();
  ExFreePoolWithTag(code, kHyperPlatformCommonPoolTag);
}

// Invalidates an instruction cache for the specified region.
_Use_decl_annotations_ static void
MmonpInvalidateInstructionCache(void *base_address, SIZE_T length) {
#if defined(_AMD64_)
  UNREFERENCED_PARAMETER(base_address);
  UNREFERENCED_PARAMETER(length);
  __faststorefence();
#elif defined(_X86_)
  UNREFERENCED_PARAMETER(base_address);
  UNREFERENCED_PARAMETER(length);
  _ReadBarrier();
#endif
}

} // extern "C"
