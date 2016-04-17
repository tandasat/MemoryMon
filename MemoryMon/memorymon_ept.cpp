// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements EPT related parts of MemoryMon.
//
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "memorymon.h"
#include "memorymon_ept.h"
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

// How many EPT entries can be disabled without being reset. When the number
// exceeds it, hypervisor reset all entries.
static const auto kMmoneptpMaxNumberOfDisabledEntries = 4096 * 5;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct MmonEptData {
  EptCommonEntry **disabled_entries;
  KSPIN_LOCK disabled_entries_lock;
  volatile long disabled_entries_count;
  volatile long disabled_entries_max_usage;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static bool MmoneptpIsCopiedKiInterruptTemplate(_In_ void *virtual_address);

_IRQL_requires_min_(DISPATCH_LEVEL) static void MmoneptpAddDisabledEntry(
    _In_ MmonEptData *ept_data, _In_ EptCommonEntry *ept_entry);

_IRQL_requires_min_(DISPATCH_LEVEL) static void MmoneptpResetDisabledEntriesUnsafe(
    _In_ MmonEptData *ept_data);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, MmoneptInitialization)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes EPT related parts of MemoryMon
_Use_decl_annotations_ MmonEptData *MmoneptInitialization(EptData *ept_data) {
  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  const auto is_v6_kernel = os_version.dwMajorVersion == 6;
  const auto pfn_database = MmonGetPfnDatabase();

  // Initialize all EPT entries for all physical memory pages
  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
       ++run_index) {
    const auto run = &pm_ranges->run[run_index];
    const auto base_addr = run->base_page * PAGE_SIZE;
    for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
      const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
      const auto ept_pt_entry = EptGetEptPtEntry(ept_data, indexed_addr);

      // Mark the page as non-executable if it is not a non-pagable section of
      // a system module.
      const auto va = UtilVaFromPa(indexed_addr);
      if (!MmonPcToFileHeader(va) ||
          !UtilIsNonPageableAddress(va, pfn_database, is_v6_kernel)) {
        ept_pt_entry->fields.execute_access = false;
      }
    }
  }

  // Allocate ept_data
  const auto mm_ept_data =
      reinterpret_cast<MmonEptData *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, sizeof(MmonEptData), kHyperPlatformCommonPoolTag));
  if (!mm_ept_data) {
    return nullptr;
  }
  RtlZeroMemory(mm_ept_data, sizeof(MmonEptData));

  // Allocate disabled_entries
  const auto disabled_entries_size =
      sizeof(EptCommonEntry *) * kMmoneptpMaxNumberOfDisabledEntries;
  const auto disabled_entries =
      reinterpret_cast<EptCommonEntry **>(ExAllocatePoolWithTag(
          NonPagedPoolNx, disabled_entries_size, kHyperPlatformCommonPoolTag));
  if (!disabled_entries) {
    ExFreePoolWithTag(mm_ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(disabled_entries, disabled_entries_size);

  mm_ept_data->disabled_entries = disabled_entries;
  mm_ept_data->disabled_entries_count = 0;
  mm_ept_data->disabled_entries_max_usage = 0;
  KeInitializeSpinLock(&mm_ept_data->disabled_entries_lock);
  return mm_ept_data;
}

// Terminates EPT related parts of MemoryMon
_Use_decl_annotations_ void MmoneptTermination(MmonEptData *mm_ept_data) {
  HYPERPLATFORM_LOG_DEBUG("Used disabled entries (Max) = %5d / %5d",
                          mm_ept_data->disabled_entries_max_usage,
                          kMmoneptpMaxNumberOfDisabledEntries);

  ExFreePoolWithTag(mm_ept_data->disabled_entries, kHyperPlatformCommonPoolTag);
  ExFreePoolWithTag(mm_ept_data, kHyperPlatformCommonPoolTag);
}

// Handles an occurence of execution of a doggy region
_Use_decl_annotations_ void MmoneptHandleDodgyRegionExecution(
    MmonEptData *ept_data, EptCommonEntry *ept_pt_entry, ULONG64 fault_pa,
    void *fault_va) {
  // Protection violation. Examine the fault physical address and handle it
  // accordingly.
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  void *image_base_va = nullptr;
  if (reinterpret_cast<ULONG_PTR>(fault_va) <
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart)) {
    // HYPER_PLATFORM_LOG_DEBUG_SAFE("[EXEC] Usr VA = %p, PA = %016llx",
    // fault_va, fault_pa);
    ept_pt_entry->fields.execute_access = true;
    MmoneptpAddDisabledEntry(ept_data, ept_pt_entry);
  } else if ((image_base_va = MmonPcToFileHeader(fault_va)) != nullptr) {
    // HYPER_PLATFORM_LOG_DEBUG_SAFE("[EXEC] Img VA = %p, PA = %016llx, Base =
    // %p", fault_va, fault_pa, image_base_va);
    ept_pt_entry->fields.execute_access = true;
    MmoneptpAddDisabledEntry(ept_data, ept_pt_entry);
  } else if (MmoneptpIsCopiedKiInterruptTemplate(fault_va)) {
    // HYPER_PLATFORM_LOG_DEBUG_SAFE("[EXEC] Int VA = %p, PA = %016llx",
    // fault_va, fault_pa);
    ept_pt_entry->fields.execute_access = true;
    // Do not add to the disabled entries list so that it never causes EPT
    // violation for this address. Since it is an interruption handler, it
    // has to be on non-paged pool and unlikely to be unmapped and reused.
  } else {
    const auto guest_sp =
        reinterpret_cast<void **>(UtilVmRead(VmcsField::kGuestRsp));
    const auto return_base_va = MmonPcToFileHeader(*guest_sp);
    HYPERPLATFORM_LOG_INFO_SAFE(
        "[EXEC] *** VA = %p, PA = %016llx, Return = %p, ReturnBase = %p",
        fault_va, fault_pa, *guest_sp, return_base_va);

    ept_pt_entry->fields.execute_access = true;
    MmoneptpAddDisabledEntry(ept_data, ept_pt_entry);
  }

  UtilInveptAll();
}

// Check if the address is a copy of KiInterruptTemplate
_Use_decl_annotations_ static bool MmoneptpIsCopiedKiInterruptTemplate(
    void *virtual_address) {
  if (IsX64()) {
    // nt!KiInterruptTemplate:
    // 50              push    rax
    // 55              push    rbp
    // 488d2d67ffffff  lea     rbp, [nt!KiInterruptDispatchNoEOI + 0x210]
    // ff6550          jmp     qword ptr[rbp + 50h]
    // cc              int     3
    // cc              int     3
    // cc              int     3
    // cc              int     3
    static const UCHAR kKiInterruptTemplate[] = {
        0x50, 0x55, 0x48, 0x8d, 0x2d, 0x67, 0xff, 0xff,
        0xff, 0xff, 0x65, 0x50, 0xcc, 0xcc, 0xcc, 0xcc,
    };
    return (RtlCompareMemory(virtual_address, kKiInterruptTemplate,
                             sizeof(kKiInterruptTemplate)) ==
            sizeof(kKiInterruptTemplate));
  } else {
    // nt!KiInterruptTemplate:
    // 54                     push    esp
    // 55                     push    ebp
    // 53                     push    ebx
    // 56                     push    esi
    // 57                     push    edi
    // 83 EC 54               sub     esp, 54h
    // 8B EC                  mov     ebp, esp
    // 89 45 44               mov     [ebp + _KTRAP_FRAME._Eax], eax
    // 89 4D 40               mov     [ebp + _KTRAP_FRAME._Ecx], ecx
    // 89 55 3C               mov     [ebp + _KTRAP_FRAME._Edx], edx
    // F7 45 70 00 00 02 00   test    [ebp + _KTRAP_FRAME.EFlags], 20000h
    static const UCHAR kKiInterruptTemplate[] = {
        0x54, 0x55, 0x53, 0x56, 0x57, 0x83, 0xEC, 0x54, 0x8B,
        0xEC, 0x89, 0x45, 0x44, 0x89, 0x4D, 0x40, 0x89, 0x55,
        0x3C, 0xF7, 0x45, 0x70, 0x00, 0x00, 0x02, 0x00,
    };
    return (RtlCompareMemory(virtual_address, kKiInterruptTemplate,
                             sizeof(kKiInterruptTemplate)) ==
            sizeof(kKiInterruptTemplate));
  }
}

// Add the EPT entry to the disabled entries array
_Use_decl_annotations_ static void MmoneptpAddDisabledEntry(
    MmonEptData *ept_data, EptCommonEntry *ept_entry) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&ept_data->disabled_entries_lock,
                                           &lock_handle);
  auto count = ept_data->disabled_entries_count;
  if (count >= kMmoneptpMaxNumberOfDisabledEntries) {
    MmoneptpResetDisabledEntriesUnsafe(ept_data);
    count = 0;
  }
  ept_data->disabled_entries[count] = ept_entry;
  ept_data->disabled_entries_count++;
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

// Clear all disabled EPT entries (ie, reset all EPT entries that were marked
// as executable to non-executable again)
_Use_decl_annotations_ void MmoneptResetDisabledEntries(MmonEptData *ept_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&ept_data->disabled_entries_lock,
                                           &lock_handle);
  MmoneptpResetDisabledEntriesUnsafe(ept_data);
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

// Clear all disabled EPT entries without spin lock
_Use_decl_annotations_ static void MmoneptpResetDisabledEntriesUnsafe(
    MmonEptData *ept_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const auto count = ept_data->disabled_entries_count;
  for (auto i = 0l; i < count; ++i) {
    auto disabledEntry = ept_data->disabled_entries[i];
    disabledEntry->fields.execute_access = false;
  }
  ept_data->disabled_entries_count = 0;
  if (count > ept_data->disabled_entries_max_usage) {
    ept_data->disabled_entries_max_usage = count;
  }
  if (count) {
    UtilInveptAll();
  }
}

}  // extern "C"
