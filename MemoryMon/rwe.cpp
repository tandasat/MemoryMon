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
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>

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

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static std::vector<AddressRange>* g_rwep_src_ranges;
static std::vector<AddressRange>* g_rwep_dst_ranges;

static KSPIN_LOCK g_rwep_src_ranges_spinlock;
static KSPIN_LOCK g_rwep_dst_ranges_spinlock;

struct rwe_last_info {
  ULONG_PTR guest_ip;
  ULONG_PTR fault_va;
  EptCommonEntry* ept_entry;
  UCHAR old_bytes[64];  // ZMM registers on AVX-512 are 512 bits
};
static rwe_last_info g_last_info;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

NTSTATUS RweInitialization() {
  g_rwep_src_ranges = new std::vector<AddressRange>();
  g_rwep_dst_ranges = new std::vector<AddressRange>();
  KeInitializeSpinLock(&g_rwep_src_ranges_spinlock);
  KeInitializeSpinLock(&g_rwep_dst_ranges_spinlock);

  return STATUS_SUCCESS;
}

void RweTermination() {
  delete g_rwep_dst_ranges;
  delete g_rwep_src_ranges;
}

void RweAddSrcRange(const AddressRange& range) {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_src_ranges_spinlock,
                                           &lock_handle);

  g_rwep_src_ranges->push_back(range);

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

void RweAddDstRange(const AddressRange& range) {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_dst_ranges_spinlock,
                                           &lock_handle);

  g_rwep_dst_ranges->push_back(range);

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
}

bool RweIsInsideSrcRange(ULONG_PTR address) {
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_rwep_src_ranges_spinlock,
                                           &lock_handle);

  bool inside = false;
  for (const auto& range : *g_rwep_src_ranges) {
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
  for (const auto& range : *g_rwep_dst_ranges) {
    if (UtilIsInBounds(address, range.start_address, range.end_address)) {
      inside = true;
      break;
    }
  }

  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
  return inside;
}

//
//
//

static void RwepSwitchToMonitoringMode() {}

static void RweSwtichToNormalMode() {}

static void RwepHandleExecuteViolation(ULONG_PTR fault_va) {
  if (RweIsInsideSrcRange(fault_va)) {
    // Someone is entering a source range
    NT_ASSERT(!RweIsInsideDstRange(fault_va));

    // Switch to
    //        E   RW
    //  Src   o   o
    //  Dst   x   x
    //  Oth   x   o
    RwepSwitchToMonitoringMode();
  } else {
    // Presumably, someone is leaving a source range
    NT_ASSERT(RweIsInsideDstRange(fault_va));

    // Switch to
    //        E   RW
    //  Src   x   o
    //  Dst   o   o
    //  Oth   o   o
    RweSwtichToNormalMode();

    const auto guest_sp =
      reinterpret_cast<void **>(UtilVmRead(VmcsField::kGuestRsp));
    const auto return_address = *guest_sp;

    // FIXME: return_address is not reliable source. 
    HYPERPLATFORM_LOG_INFO_SAFE("S= %p, D= %p, T= E", return_address, fault_va);
  }
}

static void RewpSetMonitorTrapFlag(bool enable) {
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}

static void RewpAllowReadWriteOnPage(bool allow_read_write,
                                     EptCommonEntry* ept_entry) {
  ept_entry->fields.write_access = allow_read_write;
  ept_entry->fields.read_access = allow_read_write;
  UtilInveptAll();
}

static void RewpHandleReadWriteViolation(EptData* ept_data, ULONG_PTR guest_ip,
                                         ULONG_PTR fault_va, bool is_write) {
  // most of cases. if the operation happend just outside, may be not
  NT_ASSERT(RweIsInsideDstRange(fault_va));

  NT_ASSERT(RweIsInsideSrcRange(guest_ip));
  // Read or write from a source range to a dest range

  const auto ept_entry = EptGetEptPtEntry(
      ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));

  RewpSetMonitorTrapFlag(true);
  RewpAllowReadWriteOnPage(true, ept_entry);

  g_last_info.ept_entry = ept_entry;
  if (is_write) {
    g_last_info.guest_ip = guest_ip;
    g_last_info.fault_va = fault_va;
    const auto current_cr3 = __readcr3();
    const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    __writecr3(guest_cr3);
    RtlCopyMemory(g_last_info.old_bytes, reinterpret_cast<void*>(fault_va),
                  sizeof(g_last_info.old_bytes));
    __writecr3(current_cr3);

  } else {
    g_last_info.guest_ip = 0;
    g_last_info.fault_va = 0;
    RtlZeroMemory(g_last_info.old_bytes, sizeof(g_last_info.old_bytes));
    HYPERPLATFORM_LOG_INFO_SAFE("S= %p, D= %p, T= R", guest_ip, fault_va);
  }
}

void RweHandleEptViolation(EptData* ept_data, ULONG_PTR guest_ip,
                           ULONG_PTR fault_va, bool read_violation,
                           bool write_violation, bool execute_violation) {
  if (execute_violation) {
    RwepHandleExecuteViolation(fault_va);
  } else if (read_violation || write_violation) {
    RewpHandleReadWriteViolation(ept_data, guest_ip, fault_va, write_violation);
  } else {
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                   0);
  }
}

void RweHandleMonitorTrapFlag() {
  RewpSetMonitorTrapFlag(true);
  RewpAllowReadWriteOnPage(false, g_last_info.ept_entry);

  if (g_last_info.guest_ip) {
    // last access was write

    char old_bytes_string[3 * sizeof(g_last_info.old_bytes) + 1];
    for (auto i = 0ul; i < sizeof(g_last_info.old_bytes); ++i) {
      const auto consumed_bytes = i * 3;
      const auto buffer_size = sizeof(old_bytes_string) - consumed_bytes;
      RtlStringCchPrintfA(old_bytes_string + consumed_bytes, buffer_size,
                          "%02x", g_last_info.old_bytes[i]);
    }
    old_bytes_string[sizeof(old_bytes_string) - 1] = '\0';

    UCHAR current_bytes[sizeof(g_last_info.old_bytes)];
    const auto current_cr3 = __readcr3();
    const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
    __writecr3(guest_cr3);
    RtlCopyMemory(current_bytes, reinterpret_cast<void*>(g_last_info.fault_va),
                  sizeof(current_bytes));
    __writecr3(current_cr3);

    char current_bytes_string[3 * sizeof(current_bytes) + 1];
    for (auto i = 0ul; i < sizeof(current_bytes); ++i) {
      const auto consumed_bytes = i * 3;
      const auto buffer_size = sizeof(current_bytes_string) - consumed_bytes;
      RtlStringCchPrintfA(current_bytes_string + consumed_bytes, buffer_size,
                          "%02x", current_bytes[i]);
    }
    current_bytes_string[sizeof(current_bytes_string) - 1] = '\0';

    HYPERPLATFORM_LOG_INFO_SAFE("S= %p, D= %p, T= W, %s => %s",
                                g_last_info.guest_ip, g_last_info.fault_va,
                                old_bytes_string, current_bytes_string);
  }
}

}  // extern "C"
