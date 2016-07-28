// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "rwe.h"
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/vmm.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <array>

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// memmove uses xmmN which is 128 bits
// zmmN registers on AVX-512 are 512 bits
static const auto kRwepWriteMonitorSize = 16;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct AddressRange {
  ULONG_PTR start_address;  // inclusive
  ULONG_PTR end_address;    // inclusive
};

struct rwe_last_info {
  ULONG_PTR guest_ip;
  ULONG_PTR fault_va;
  EptCommonEntry* ept_entry;
  std::array<UCHAR, kRwepWriteMonitorSize> old_bytes;
};

struct VitualAndPhysicalMap {
  void* va;
  ULONG64 pa;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static std::vector<AddressRange> g_rwep_src_ranges;
static std::vector<AddressRange> g_rwep_dst_ranges;

static KSPIN_LOCK g_rwep_src_ranges_spinlock;
static KSPIN_LOCK g_rwep_dst_ranges_spinlock;

static rwe_last_info g_rwep_last_info;

static std::vector<VitualAndPhysicalMap> g_rwep_vp_maps;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

NTSTATUS RweInitialization() {
  KeInitializeSpinLock(&g_rwep_src_ranges_spinlock);
  KeInitializeSpinLock(&g_rwep_dst_ranges_spinlock);
  return STATUS_SUCCESS;
}

void RweTermination() {}

//
void RewpAddToMap(const AddressRange& range) {
  auto& vp_maps = g_rwep_vp_maps;

  const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
      range.start_address, range.end_address - range.start_address + 1);
  for (auto page_index = 0ul; page_index < pages; ++page_index) {
    const auto va_base =
        PAGE_ALIGN(range.start_address + PAGE_SIZE * page_index);
    const auto pa_base = UtilPaFromVa(va_base);
    VitualAndPhysicalMap map = {va_base, pa_base};
    vp_maps.push_back(map);

    HYPERPLATFORM_LOG_DEBUG("Map: V:%p P:%p", map.va, map.pa);
  }
}

//
// Range Manipulation
//
void RweAddSrcRange(ULONG_PTR address, SIZE_T size) {
  AddressRange range = {address, address + size - 1};
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add SRC rabge: %p - %p", range.start_address,
                               range.end_address);

  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_src_ranges_spinlock,
                                           &lock_handle);

  g_rwep_src_ranges.push_back(range);

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);

  RewpAddToMap(range);
}

void RweAddDstRange(ULONG_PTR address, SIZE_T size) {
  AddressRange range = {address, address + size - 1};
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add DST rabge: %p - %p", range.start_address,
                               range.end_address);

  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_dst_ranges_spinlock,
                                           &lock_handle);

  g_rwep_dst_ranges.push_back(range);

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);

  RewpAddToMap(range);
}

bool RweIsInsideSrcRange(ULONG_PTR address) {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_src_ranges_spinlock,
                                           &lock_handle);

  bool inside = false;
  for (const auto& range : g_rwep_src_ranges) {
    if (UtilIsInBounds(address, range.start_address, range.end_address)) {
      inside = true;
      break;
    }
  }

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
  return inside;
}

bool RweIsInsideDstRange(ULONG_PTR address) {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_dst_ranges_spinlock,
                                           &lock_handle);

  bool inside = false;
  for (const auto& range : g_rwep_dst_ranges) {
    if (UtilIsInBounds(address, range.start_address, range.end_address)) {
      inside = true;
      break;
    }
  }

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
  return inside;
}

// Make all non-executable for MONITOR
void RweSetDefaultEptAttributes(ProcessorData* processor_data) {
  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
       ++run_index) {
    const auto run = &pm_ranges->run[run_index];
    const auto base_addr = run->base_page * PAGE_SIZE;
    for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
      const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
      const auto ept_entry =
          EptGetEptPtEntry(processor_data->ept_data_monitor, indexed_addr);

      ept_entry->fields.execute_access = false;
    }
  }
  HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL : S:RWE D:RWE O:RWE *");
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RW- D:RW- O:RW- *");
}

// Apply ranges to EPT attributes
void RweApplyRanges() {
  UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kRweApplyRanges, nullptr);
      },
      nullptr);
}

//
// VMM code
//
static void RweSwtichToNormalMode(_Inout_ ProcessorData* processor_data) {
  processor_data->ept_data = processor_data->ept_data_normal;
  UtilVmWrite64(VmcsField::kEptPointer,
                EptGetEptPointer(processor_data->ept_data));
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR => NORMAL");
  UtilInveptAll();
}

static void RwepSwitchToMonitoringMode(_Inout_ ProcessorData* processor_data) {
  processor_data->ept_data = processor_data->ept_data_monitor;
  UtilVmWrite64(VmcsField::kEptPointer,
                EptGetEptPointer(processor_data->ept_data));
  HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL  => MONITOR");
  UtilInveptAll();
}

static void RwepHandleExecuteViolation(_Inout_ ProcessorData* processor_data,
                                       ULONG_PTR fault_va) {
  if (RweIsInsideSrcRange(fault_va)) {
    // Someone is entering a source range

    // RweHandleTlbFlush(processor_data);

    // Currently
    //        E   RW
    //  Src   x   o
    //  Dst   o   o
    //  Oth   o   o
    NT_ASSERT(!RweIsInsideDstRange(fault_va));

    // Switch to
    //        E   RW
    //  Src   o   o
    //  Dst   x   x
    //  Oth   x   o
    RwepSwitchToMonitoringMode(processor_data);

    const auto guest_sp =
        reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
    const auto return_address = *guest_sp;
    // TODO: IsExecutable?
    HYPERPLATFORM_LOG_INFO_SAFE("R= %p, D= %p, T= E", return_address, fault_va);

  } else {
    // Presumably, someone is leaving a source range

    // Currently
    //        E   RW
    //  Src   o   o
    //  Dst   x   x
    //  Oth   x   o

    // Switch to
    //        E   RW
    //  Src   x   o
    //  Dst   o   o
    //  Oth   o   o
    RweSwtichToNormalMode(processor_data);

    const auto guest_sp =
        reinterpret_cast<ULONG_PTR*>(UtilVmRead(VmcsField::kGuestRsp));
    const auto return_address = *guest_sp;

    // Log only when a return address is inside a source range. By this, we
    // ignore following cases:
    //    - RET from a source range to other range
    //    - conditional and unconditional jump from a source range to other
    //    range
    if (RweIsInsideSrcRange(return_address)) {
      HYPERPLATFORM_LOG_INFO_SAFE("R= %p, D= %p, T= E", return_address,
                                  fault_va);
    }
  }
}

static void RewpSetMonitorTrapFlag(bool enable) {
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}

static void RewpSetReadWriteOnPage(bool allow_read_write,
                                   EptCommonEntry* ept_entry) {
  ept_entry->fields.write_access = allow_read_write;
  ept_entry->fields.read_access = allow_read_write;
  UtilInveptAll();
}

static void RewpHandleReadWriteViolation(EptData* ept_data, ULONG_PTR guest_ip,
                                         ULONG_PTR fault_va, bool is_write) {
  auto& last_info = g_rwep_last_info;
  NT_ASSERT(!last_info.ept_entry);

  // Read or write from a source range to a dest range
  NT_ASSERT(RweIsInsideSrcRange(guest_ip));

  // Currently
  //        E   RW
  //  Src   o   o
  //  Dst   x   x
  //  Oth   x   o

  // most of cases. if the operation happend just outside, may be not
  NT_ASSERT(RweIsInsideDstRange(fault_va));

  const auto ept_entry = EptGetEptPtEntry(
      ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));

  // Tempolarily switch to
  //        E   RW
  //  Src   o   o
  //  Dst   x   o
  //  Oth   x   o
  RewpSetReadWriteOnPage(true, ept_entry);
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p",
                               PAGE_ALIGN(fault_va));
  RewpSetMonitorTrapFlag(true);

  last_info.ept_entry = ept_entry;
  if (is_write) {
    last_info.guest_ip = guest_ip;
    last_info.fault_va = fault_va;
    const auto current_cr3 = __readcr3();
    const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    __writecr3(guest_cr3);
    RtlCopyMemory(last_info.old_bytes.data(), reinterpret_cast<void*>(fault_va),
                  last_info.old_bytes.size());
    __writecr3(current_cr3);

  } else {
    last_info.guest_ip = 0;
    last_info.fault_va = 0;
    RtlZeroMemory(last_info.old_bytes.data(), last_info.old_bytes.size());
    HYPERPLATFORM_LOG_INFO_SAFE("S= %p, D= %p, T= R", guest_ip, fault_va);
  }
}

void RweHandleEptViolation(ProcessorData* processor_data, ULONG_PTR guest_ip,
                           ULONG_PTR fault_va, bool read_violation,
                           bool write_violation, bool execute_violation) {
  // HYPERPLATFORM_COMMON_DBG_BREAK();

  if (execute_violation) {
    RwepHandleExecuteViolation(processor_data, fault_va);
  } else if (read_violation || write_violation) {
    RewpHandleReadWriteViolation(processor_data->ept_data, guest_ip, fault_va,
                                 write_violation);
  } else {
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                   0);
  }
}

void RweHandleMonitorTrapFlag() {
  // HYPERPLATFORM_COMMON_DBG_BREAK();
  auto& last_info = g_rwep_last_info;
  NT_ASSERT(last_info.ept_entry);

  // Revert to
  //        E   RW
  //  Src   o   o
  //  Dst   x   x
  //  Oth   x   o
  RewpSetReadWriteOnPage(false, last_info.ept_entry);
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:--- O:RW- %p",
                               PAGE_ALIGN(last_info.fault_va));
  RewpSetMonitorTrapFlag(false);

  // was the last access write?
  if (last_info.guest_ip) {
    char old_bytes_string[3 * sizeof(last_info.old_bytes)];
    for (auto i = 0ul; i < sizeof(last_info.old_bytes); ++i) {
      const auto consumed_bytes = i * 3;
      const auto buffer_size = sizeof(old_bytes_string) - consumed_bytes;
      RtlStringCchPrintfA(old_bytes_string + consumed_bytes, buffer_size,
                          "%02x ", last_info.old_bytes[i]);
    }
    old_bytes_string[sizeof(old_bytes_string) - 1] = '\0';

    UCHAR current_bytes[sizeof(last_info.old_bytes)];
    const auto current_cr3 = __readcr3();
    const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    __writecr3(guest_cr3);
    RtlCopyMemory(current_bytes, reinterpret_cast<void*>(last_info.fault_va),
                  sizeof(current_bytes));
    __writecr3(current_cr3);

    char current_bytes_string[3 * sizeof(current_bytes)];
    for (auto i = 0ul; i < sizeof(current_bytes); ++i) {
      const auto consumed_bytes = i * 3;
      const auto buffer_size = sizeof(current_bytes_string) - consumed_bytes;
      RtlStringCchPrintfA(current_bytes_string + consumed_bytes, buffer_size,
                          "%02x ", current_bytes[i]);
    }
    current_bytes_string[sizeof(current_bytes_string) - 1] = '\0';

    HYPERPLATFORM_LOG_INFO_SAFE("S= %p, D= %p, T= W, %s => %s",
                                last_info.guest_ip, last_info.fault_va,
                                old_bytes_string, current_bytes_string);

    last_info.guest_ip = 0;
    last_info.fault_va = 0;
    RtlZeroMemory(last_info.old_bytes.data(), last_info.old_bytes.size());
  }
  last_info.ept_entry = nullptr;
}

// Apply ranges to EPT attributes
void RweVmcallApplyRanges(ProcessorData* processor_data) {
  NT_ASSERT(processor_data->ept_data == processor_data->ept_data_normal);

  // Make source ranges non-executable for normal pages and executable for
  // monitor pages
  for (const auto& src_ragne : g_rwep_src_ranges) {
    const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        src_ragne.start_address,
        src_ragne.end_address - src_ragne.start_address + 1);
    for (auto page_index = 0ul; page_index < pages; ++page_index) {
      const auto va = src_ragne.start_address + PAGE_SIZE * page_index;
      const auto pa = UtilPaFromVa(reinterpret_cast<void*>(va));
      if (!pa) {
        HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.",
                                     va);
        continue;
      }

      const auto ept_entry_n =
          EptGetEptPtEntry(processor_data->ept_data_normal, pa);
      ept_entry_n->fields.execute_access = false;

      const auto ept_entry_m =
          EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
      ept_entry_m->fields.execute_access = true;

      HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL : S:RW- D:RWE O:RWE %p",
                                   PAGE_ALIGN(va));
      HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p",
                                   PAGE_ALIGN(va));
    }
  }

  // Make dest ranges non-readable/writable/executable for monitor pages
  for (const auto& dst_ragne : g_rwep_dst_ranges) {
    const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        dst_ragne.start_address,
        dst_ragne.end_address - dst_ragne.start_address + 1);
    for (auto page_index = 0ul; page_index < pages; ++page_index) {
      const auto va = dst_ragne.start_address + PAGE_SIZE * page_index;
      const auto pa = UtilPaFromVa(reinterpret_cast<void*>(va));
      if (!pa) {
        HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.",
                                     va);
        continue;
      }

      const auto ept_entry =
          EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
      ept_entry->fields.execute_access = false;
      ept_entry->fields.write_access = false;
      ept_entry->fields.read_access = false;
      HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:--- O:RW- %p",
                                   PAGE_ALIGN(va));
    }
  }

  UtilInveptAll();
}

void RweHandleTlbFlush(ProcessorData* processor_data) {
  auto& vp_maps = g_rwep_vp_maps;
  bool need_refresh = false;

  for (auto& map : vp_maps) {
    NT_ASSERT(map.va == PAGE_ALIGN(map.va));
    NT_ASSERT(map.pa == (ULONG64)PAGE_ALIGN(map.pa));
    const auto new_pa = UtilPaFromVa(map.va);
    if (new_pa != map.pa) {
      need_refresh = true;

      if (map.pa) {
        const auto old_ept_entry_n =
            EptGetEptPtEntry(processor_data->ept_data_normal, map.pa);
        const auto old_ept_entry_m =
            EptGetEptPtEntry(processor_data->ept_data_monitor, map.pa);
        NT_ASSERT(old_ept_entry_n && old_ept_entry_n->all);
        NT_ASSERT(old_ept_entry_m && old_ept_entry_m->all);

        old_ept_entry_n->fields.read_access = true;
        old_ept_entry_n->fields.write_access = true;
        old_ept_entry_n->fields.execute_access = true;
        old_ept_entry_m->fields.read_access = true;
        old_ept_entry_m->fields.write_access = true;
        // monitor pages are not executable by default
        old_ept_entry_m->fields.execute_access = false;
      }

      HYPERPLATFORM_LOG_DEBUG_SAFE("Map: V:%p P:%p => %p", map.va, map.pa,
                                   new_pa);
      map.pa = new_pa;
    }
  }

  if (need_refresh) {
    RweVmcallApplyRanges(processor_data);
  }
}

///////////////////////////////////////////////////////////////////////////////

static ULONG_PTR g_pfp_last_ip;

#pragma section(".asm", read, execute)
__declspec(allocate(".asm")) static const UCHAR PageFaultpBreakPoint[] = {0xcc};

void PageFaultpHanlePageFault(void* guest_ip, ULONG_PTR fault_address) {
  UNREFERENCED_PARAMETER(guest_ip);
  UNREFERENCED_PARAMETER(fault_address);

  if (guest_ip < MmSystemRangeStart) {
    return;
  }
  if (g_pfp_last_ip) {
    return;
  }

  // Update guest's IP
  UtilVmWrite(VmcsField::kGuestRip, (ULONG_PTR)&PageFaultpBreakPoint);

  NT_ASSERT(!g_pfp_last_ip);
  g_pfp_last_ip = (ULONG_PTR)guest_ip;
}

bool PageFaultpHandleBreakpoint(void* guest_ip, ProcessorData* processor_data) {
  if (guest_ip != PageFaultpBreakPoint) {
    return false;
  }

  // HYPERPLATFORM_COMMON_DBG_BREAK();

  NT_ASSERT(g_pfp_last_ip);
  const auto original_ip = g_pfp_last_ip;
  g_pfp_last_ip = 0;

  // Update guest's IP
  UtilVmWrite(VmcsField::kGuestRip, original_ip);
  RweHandleTlbFlush(processor_data);
  return true;
}

}  // extern "C"
