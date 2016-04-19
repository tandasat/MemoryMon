// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Implements EPT related parts of MemoryMon

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

// How many pages can be saved as ones already logged and should not be printed
// out again.
static const auto kMmoneptpMaxNumberOfLoggedEntries = 1024;

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
    _In_ MmonEptData *mmon_ept_data, _In_ EptCommonEntry *ept_entry);

_IRQL_requires_min_(DISPATCH_LEVEL) static void MmoneptpResetDisabledEntriesUnsafe(
    _In_ MmonEptData *mmon_ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) static bool MmoneptpAddToLoggedPages(
    _In_ ULONG64 fault_pa);

_IRQL_requires_min_(DISPATCH_LEVEL) static void MmoneptpClearLoggedPages();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, MmoneptInitialization)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// An array of PNFs already logged as an executed dodgy page. It is used to
// avoid logging the same page twice for different processors by sharing
// executed dodgy memory pages across processors.
static PFN_NUMBER g_mmoneptp_logged_pages[kMmoneptpMaxNumberOfLoggedEntries];
static KSPIN_LOCK g_mmoneptp_logged_pages_skinlock;

// Indicates how many entries are being used. MAXLONG indicates that related
// data structures are uninitialized.
static volatile long g_mmoneptp_logged_pages_index = MAXLONG;

// Indicates how many entries are used as most.
static long g_mmoneptp_logged_pages_max_usage = 0;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes EPT related parts of MemoryMon
_Use_decl_annotations_ MmonEptData *MmoneptInitialization(EptData *ept_data) {
  if (g_mmoneptp_logged_pages_index == MAXLONG) {
    g_mmoneptp_logged_pages_index = 0;
    KeInitializeSpinLock(&g_mmoneptp_logged_pages_skinlock);
  }

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
      if (!UtilPcToFileHeader(va) ||
          !UtilIsNonPageableAddress(va, pfn_database, is_v6_kernel)) {
        ept_pt_entry->fields.execute_access = false;
      }
    }
  }

  // Allocate mmon_ept_data
  const auto mmon_ept_data =
      reinterpret_cast<MmonEptData *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, sizeof(MmonEptData), kHyperPlatformCommonPoolTag));
  if (!mmon_ept_data) {
    return nullptr;
  }
  RtlZeroMemory(mmon_ept_data, sizeof(MmonEptData));

  // Allocate disabled_entries
  const auto disabled_entries_size =
      sizeof(EptCommonEntry *) * kMmoneptpMaxNumberOfDisabledEntries;
  const auto disabled_entries =
      reinterpret_cast<EptCommonEntry **>(ExAllocatePoolWithTag(
          NonPagedPoolNx, disabled_entries_size, kHyperPlatformCommonPoolTag));
  if (!disabled_entries) {
    ExFreePoolWithTag(mmon_ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(disabled_entries, disabled_entries_size);

  mmon_ept_data->disabled_entries = disabled_entries;
  mmon_ept_data->disabled_entries_count = 0;
  mmon_ept_data->disabled_entries_max_usage = 0;
  KeInitializeSpinLock(&mmon_ept_data->disabled_entries_lock);
  return mmon_ept_data;
}

// Terminates EPT related parts of MemoryMon
_Use_decl_annotations_ void MmoneptTermination(MmonEptData *mmon_ept_data) {
  // Prints out only once
  if (g_mmoneptp_logged_pages_max_usage != MAXLONG) {
    HYPERPLATFORM_LOG_DEBUG("Used logged entries (Max) = %5d / %5d",
                            g_mmoneptp_logged_pages_max_usage,
                            kMmoneptpMaxNumberOfLoggedEntries);
    // Mark as already-printed
    g_mmoneptp_logged_pages_max_usage = MAXLONG;
  }

  HYPERPLATFORM_LOG_DEBUG("Used disabled entries (Max) = %5d / %5d",
                          mmon_ept_data->disabled_entries_max_usage,
                          kMmoneptpMaxNumberOfDisabledEntries);

  ExFreePoolWithTag(mmon_ept_data->disabled_entries,
                    kHyperPlatformCommonPoolTag);
  ExFreePoolWithTag(mmon_ept_data, kHyperPlatformCommonPoolTag);
}

// Handles an occurence of execution of a doggy region
_Use_decl_annotations_ void MmoneptHandleDodgyRegionExecution(
    MmonEptData *mmon_ept_data, EptCommonEntry *ept_pt_entry, ULONG64 fault_pa,
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
    MmoneptpAddDisabledEntry(mmon_ept_data, ept_pt_entry);
  } else if ((image_base_va = UtilPcToFileHeader(fault_va)) != nullptr) {
    // HYPER_PLATFORM_LOG_DEBUG_SAFE("[EXEC] Img VA = %p, PA = %016llx, Base =
    // %p", fault_va, fault_pa, image_base_va);
    ept_pt_entry->fields.execute_access = true;
    MmoneptpAddDisabledEntry(mmon_ept_data, ept_pt_entry);
  } else if (MmoneptpIsCopiedKiInterruptTemplate(fault_va)) {
    // HYPER_PLATFORM_LOG_DEBUG_SAFE("[EXEC] Int VA = %p, PA = %016llx",
    // fault_va, fault_pa);
    ept_pt_entry->fields.execute_access = true;
    // Do not add to the disabled entries list so that it never causes EPT
    // violation for this address. Since it is an interruption handler, it
    // has to be on non-paged pool and unlikely to be unmapped and reused.
  } else {
    ept_pt_entry->fields.execute_access = true;
    MmoneptpAddDisabledEntry(mmon_ept_data, ept_pt_entry);

    // Add the page to the logged pages and log it when it is not already logged
    if (!MmoneptpAddToLoggedPages(fault_pa)) {
      const auto guest_sp =
          reinterpret_cast<void **>(UtilVmRead(VmcsField::kGuestRsp));
      const auto return_base_va = UtilPcToFileHeader(*guest_sp);
      HYPERPLATFORM_LOG_INFO_SAFE(
          "[EXEC] *** VA = %p, PA = %016llx, Return = %p, ReturnBase = %p",
          fault_va, fault_pa, *guest_sp, return_base_va);
    }
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
    MmonEptData *mmon_ept_data, EptCommonEntry *ept_entry) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(
      &mmon_ept_data->disabled_entries_lock, &lock_handle);
  auto count = mmon_ept_data->disabled_entries_count;
  if (count >= kMmoneptpMaxNumberOfDisabledEntries) {
    MmoneptpResetDisabledEntriesUnsafe(mmon_ept_data);
    count = 0;
  }
  mmon_ept_data->disabled_entries[count] = ept_entry;
  mmon_ept_data->disabled_entries_count++;
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

// Clear all disabled EPT entries (ie, reset all EPT entries that were marked
// as executable to non-executable again)
_Use_decl_annotations_ void MmoneptResetDisabledEntries(
    MmonEptData *mmon_ept_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(
      &mmon_ept_data->disabled_entries_lock, &lock_handle);
  MmoneptpResetDisabledEntriesUnsafe(mmon_ept_data);
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

// Clear all disabled EPT entries without spin lock
_Use_decl_annotations_ static void MmoneptpResetDisabledEntriesUnsafe(
    MmonEptData *mmon_ept_data) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const auto count = mmon_ept_data->disabled_entries_count;
  for (auto i = 0l; i < count; ++i) {
    auto disabledEntry = mmon_ept_data->disabled_entries[i];
    disabledEntry->fields.execute_access = false;
  }
  mmon_ept_data->disabled_entries_count = 0;
  if (count > mmon_ept_data->disabled_entries_max_usage) {
    mmon_ept_data->disabled_entries_max_usage = count;
  }
  if (count) {
    UtilInveptAll();
  }
  MmoneptpClearLoggedPages();
}

// Returns if \a fault_pa is in the logged pages and adds \a fault_pa to the
// logged pages if not added yet.
_Use_decl_annotations_ static bool MmoneptpAddToLoggedPages(ULONG64 fault_pa) {
  const auto fault_pfn = UtilPfnFromPa(fault_pa);
  bool already_logged = false;

  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_mmoneptp_logged_pages_skinlock,
                                           &lock_handle);

  // Check if the pfn is already logged
  for (auto i = 0l; i < g_mmoneptp_logged_pages_index; ++i) {
    const auto logged_pfn = g_mmoneptp_logged_pages[i];
    if (logged_pfn == fault_pfn) {
      already_logged = true;
      HYPERPLATFORM_LOG_DEBUG_SAFE("Execution on %p was filtered.", fault_pa);
      break;
    }
  }

  // If not, add it when possible
  if (!already_logged) {
    if (g_mmoneptp_logged_pages_index == kMmoneptpMaxNumberOfLoggedEntries) {
      HYPERPLATFORM_LOG_WARN_SAFE(
          "Logged entry is full. Any new dodgy execution will no longer be "
          "filtered.");
    } else {
      // There is room to add this pfn. Add it.
      g_mmoneptp_logged_pages[g_mmoneptp_logged_pages_index] = fault_pfn;
      g_mmoneptp_logged_pages_index++;
      // Updated max usage if needed
      if (g_mmoneptp_logged_pages_index > g_mmoneptp_logged_pages_max_usage) {
        g_mmoneptp_logged_pages_max_usage = g_mmoneptp_logged_pages_index;
      }
    }
  }

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
  return already_logged;
}

// Empties the logged pages
_Use_decl_annotations_ static void MmoneptpClearLoggedPages() {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_mmoneptp_logged_pages_skinlock,
                                           &lock_handle);
  const auto size =
      g_mmoneptp_logged_pages_index * sizeof(g_mmoneptp_logged_pages[0]);
  RtlFillMemory(g_mmoneptp_logged_pages, size, 0);
  g_mmoneptp_logged_pages_index = 0;
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

}  // extern "C"
