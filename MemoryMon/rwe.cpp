// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements RWE functions.

#include "rwe.h"
#include "scoped_lock.h"
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/vmm.h"
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif  // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "../HyperPlatform/HyperPlatform/performance.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <array>

#pragma warning(disable : 4189)

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// xmmN is 128 bits (memmove etc)
// zmmN is 512 bits (AVX-512)
static const auto kRwepNumOfMonitoredBytesForWrite = 16;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct AddressRange {
  void* start_address;  // inclusive
  void* end_address;    // inclusive
};

struct RweLastData {
  bool is_write;
  void* guest_ip;
  void* fault_va;
  EptCommonEntry* ept_entry;
  std::array<UCHAR, kRwepNumOfMonitoredBytesForWrite> old_bytes;

  RweLastData()
      : is_write(false), guest_ip(0), fault_va(0), ept_entry(nullptr) {}
};

class AddressRanges {
 public:
  AddressRanges() { KeInitializeSpinLock(&ranges_spinlock_); }

  void add(const AddressRange& range) {
    // ScopedLock lock(&ranges_spinlock_);

    // const auto position = std::find_if(
    //  ranges_.begin(), ranges_.end(),
    //  [range](const auto& elem) { return (range.start_address ==
    //  elem.start_address
    //    && range.end_address == elem.end_address); });
    // if (position != ranges_.end()) {
    //  return;   // duplicated; ignore it
    //}

    ranges_.push_back(range);
  }

  bool is_in_range(void* address) const {
    // ScopedLock lock(&ranges_spinlock_);

    bool inside = false;
    for (const auto& range : ranges_) {
      if (UtilIsInBounds(address, range.start_address, range.end_address)) {
        inside = true;
        break;
      }
    }
    return inside;
  }

  using ForEachCallback = bool (*)(_In_ void* va, _In_ ULONG64 pa,
                                   _In_opt_ void* context);

  void for_each_page(ForEachCallback callback, void* context) {
    // ScopedLock lock(&ranges_spinlock_);

    for (const auto& range : ranges_) {
      const auto start_address =
          reinterpret_cast<ULONG_PTR>(range.start_address);
      const auto end_address = reinterpret_cast<ULONG_PTR>(range.end_address);
      const auto num_of_pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
          start_address, end_address - start_address + 1);
      for (auto page_index = 0ul; page_index < num_of_pages; ++page_index) {
        const auto va =
            reinterpret_cast<void*>(start_address + PAGE_SIZE * page_index);
        const auto pa = UtilPaFromVa(va);
        if (!callback(va, pa, context)) {
          break;
        }
      }
    }
  }

 private:
  std::vector<AddressRange> ranges_;
  mutable KSPIN_LOCK ranges_spinlock_;
};

class V2PMap2 {
 public:
  V2PMap2() { KeInitializeSpinLock(&v2p_map_spinlock_); }

  void add(const AddressRange& range) {
    // ScopedLock lock(&v2p_map_spinlock_);
    const auto start_address = reinterpret_cast<ULONG_PTR>(range.start_address);
    const auto end_address = reinterpret_cast<ULONG_PTR>(range.end_address);

    const auto pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        start_address, end_address - start_address + 1);
    for (auto page_index = 0ul; page_index < pages; ++page_index) {
      const auto va_base = PAGE_ALIGN(start_address + PAGE_SIZE * page_index);
      const auto pa_base = UtilPaFromVa(va_base);
      v2p_map_.push_back(V2PMapEntry{va_base, pa_base});

      // HYPERPLATFORM_LOG_DEBUG("Map: V:%p P:%p", va_base, pa_base);
    }
  }

  bool refresh(ProcessorData* processor_data) {
    // ScopedLock lock(&v2p_map_spinlock_);

    bool need_refresh = false;
    for (auto& map : v2p_map_) {
      NT_ASSERT(map.va == PAGE_ALIGN(map.va));
      NT_ASSERT(map.pa == reinterpret_cast<ULONG64>(PAGE_ALIGN(map.pa)));
      const auto new_pa = UtilPaFromVa(map.va);
      if (new_pa == map.pa) {
        continue;
      }

      if (map.pa) {
        const auto old_ept_entry_n =
            EptGetEptPtEntry(processor_data->ept_data_normal, map.pa);
        const auto old_ept_entry_m =
            EptGetEptPtEntry(processor_data->ept_data_monitor, map.pa);
        NT_ASSERT(old_ept_entry_n && old_ept_entry_n->all);
        NT_ASSERT(old_ept_entry_m && old_ept_entry_m->all);

        old_ept_entry_n->fields.execute_access = true;
        old_ept_entry_n->fields.read_access = true;
        old_ept_entry_n->fields.write_access = true;

        // monitor pages are not executable by default
        old_ept_entry_m->fields.execute_access = false;
        old_ept_entry_m->fields.read_access = true;
        old_ept_entry_m->fields.write_access = true;
      }

      HYPERPLATFORM_LOG_DEBUG_SAFE("Map: V:%p P:%p => %p", map.va, map.pa,
                                   new_pa);
      map.pa = new_pa;
      need_refresh = true;
    }
    return need_refresh;
  }

 private:
  struct V2PMapEntry {
    void* va;
    ULONG64 pa;
  };

  std::vector<V2PMapEntry> v2p_map_;
  mutable KSPIN_LOCK v2p_map_spinlock_;
};

struct RweData {
  RweLastData last_data;
};

struct RweSharedData {
  AddressRanges src_ranges;
  AddressRanges dst_ranges;
  V2PMap2 v2p_map;
};

extern "C" {

static RweSharedData g_rwep_shared_data;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static KDEFERRED_ROUTINE RwepApplyRangesDpcRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, RweAllocData)
#pragma alloc_text(INIT, RweSetDefaultEptAttributes)
#pragma alloc_text(PAGE, RweFreeData)
#pragma alloc_text(PAGE, RweApplyRanges)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ RweData* RweAllocData() {
  PAGED_CODE();
  return new RweData;
}

_Use_decl_annotations_ void RweFreeData(RweData* rwe_data) {
  PAGED_CODE();
  delete rwe_data;
}

_Use_decl_annotations_ void RweAddSrcRange(void* address, SIZE_T size) {
  AddressRange range = {
      address,
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1)};
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add SRC range: %p - %p", range.start_address,
                               range.end_address);
  g_rwep_shared_data.src_ranges.add(range);
  g_rwep_shared_data.v2p_map.add(range);
}

_Use_decl_annotations_ void RweAddDstRange(void* address, SIZE_T size) {
  AddressRange range = {
      address,
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1)};
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add DST range: %p - %p", range.start_address,
                               range.end_address);
  g_rwep_shared_data.dst_ranges.add(range);
  g_rwep_shared_data.v2p_map.add(range);
}

_Use_decl_annotations_ bool RweIsInsideSrcRange(void* address) {
  return g_rwep_shared_data.src_ranges.is_in_range(address);
}

_Use_decl_annotations_ bool RweIsInsideDstRange(void* address) {
  return g_rwep_shared_data.dst_ranges.is_in_range(address);
}

// Make all non-executable for MONITOR
_Use_decl_annotations_ void RweSetDefaultEptAttributes(
    ProcessorData* processor_data) {
  PAGED_CODE();

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
}

// Apply ranges to EPT attributes
_Use_decl_annotations_ void RweApplyRanges() {
  PAGED_CODE();

  UtilForEachProcessor(
      [](void* context) {
        UNREFERENCED_PARAMETER(context);
        return UtilVmCall(HypercallNumber::kRweApplyRanges, nullptr);
      },
      nullptr);
}

_Use_decl_annotations_ static void RwepApplyRangesDpcRoutine(
    _KDPC* dpc, PVOID deferred_context, PVOID system_argument1,
    PVOID system_argument2) {
  UNREFERENCED_PARAMETER(deferred_context);
  UNREFERENCED_PARAMETER(system_argument1);
  UNREFERENCED_PARAMETER(system_argument2);

  UtilVmCall(HypercallNumber::kRweApplyRanges, nullptr);
  ExFreePoolWithTag(dpc, kHyperPlatformCommonPoolTag);
}

//
// VMM code
//
static void RweSwtichToNormalMode(_Inout_ ProcessorData* processor_data);
static void RwepSwitchToMonitoringMode(_Inout_ ProcessorData* processor_data);
static void RwepHandleExecuteViolation(_Inout_ ProcessorData* processor_data,
                                       _In_ void* fault_va);
static void RewpSetMonitorTrapFlag(_In_ bool enable);
static void RewpSetReadWriteOnPage(_In_ bool allow_read_write,
                                   _Out_ EptCommonEntry* ept_entry);
static void* RwepContextCopyMemory(_Out_ void* destination,
                                   _In_ const void* source, _In_ SIZE_T length);
static void RewpHandleReadWriteViolation(_Inout_ ProcessorData* processor_data,
                                         _In_ void* guest_ip,
                                         _In_ void* fault_va,
                                         _In_ bool is_write);
static NTSTATUS RwepBytesToString(_Out_ char* buffer, _In_ SIZE_T buffer_size,
                                  _In_ const UCHAR* bytes,
                                  _In_ SIZE_T bytes_size);

_Use_decl_annotations_ static void RweSwtichToNormalMode(
    ProcessorData* processor_data) {
  processor_data->ept_data = processor_data->ept_data_normal;
  UtilVmWrite64(VmcsField::kEptPointer,
                EptGetEptPointer(processor_data->ept_data));
  // HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR => NORMAL");
  UtilInveptAll();
}

_Use_decl_annotations_ static void RwepSwitchToMonitoringMode(
    ProcessorData* processor_data) {
  processor_data->ept_data = processor_data->ept_data_monitor;
  UtilVmWrite64(VmcsField::kEptPointer,
                EptGetEptPointer(processor_data->ept_data));
  // HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL  => MONITOR");
  UtilInveptAll();
}

#include <pshpack1.h>
typedef struct {
  USHORT IDTLimit;
  USHORT LowIDTbase;
  USHORT HiIDTbase;
} IDTINFO;

typedef struct {
  USHORT Offset;
  USHORT Selector;
  union {
    USHORT Access;
    struct {
      UCHAR Unused;
      UCHAR Type : 4;  // 0101(0x5) = Task Gates
                       // 1110(0xE) = Interrupt Gates
                       // 1111(0xF) = Trap Gates
      UCHAR System : 1;
      UCHAR Dpl : 2;
      UCHAR Present : 1;
    } AccessField;
  };
  USHORT ExtendedOffset;
} IDTENTRY;

/*
1: kd> dt nt!_kIDTENTRY64
   +0x000 OffsetLow        : Uint2B
   +0x002 Selector         : Uint2B
   +0x004 IstIndex         : Pos 0, 3 Bits
   +0x004 Reserved0        : Pos 3, 5 Bits
   +0x004 Type             : Pos 8, 5 Bits
   +0x004 Dpl              : Pos 13, 2 Bits
   +0x004 Present          : Pos 15, 1 Bit
   +0x006 OffsetMiddle     : Uint2B
   +0x008 OffsetHigh       : Uint4B
   +0x00c Reserved1        : Uint4B
   +0x000 Alignment        : Uint8B
*/

typedef struct {
  USHORT OffsetLow;
  USHORT Selector;
  union {
    USHORT Access;
    struct {
      USHORT IstIndex : 3;
      USHORT Reserved0 : 5;
      USHORT Type : 5;  // 0101(0x5) = Task Gates
                        // 1110(0xE) = Interrupt Gates
                        // 1111(0xF) = Trap Gates
      USHORT Dpl : 2;
      USHORT Present : 1;
    } AccessField;
  };
  USHORT OffsetMiddle;
  ULONG OffsetHigh;
  ULONG Reserved1;
} IDTENTRY64;
static_assert(sizeof(IDTENTRY64) == 0x10, "Size check");
#include <poppack.h>

static void* g_handlers[0xff] = {};
static ULONG64 g_handlers_counter[0xff] = {};
static bool g_handlers_initialized = false;

static bool RwepIsInterruptHandler(void* addr) {
  if (!g_handlers_initialized) {
    HYPERPLATFORM_COMMON_DBG_BREAK();
    Idtr idtr = {};
    __sidt(&idtr);

    const auto entries = reinterpret_cast<IDTENTRY64*>(idtr.base);
    for (auto i = 0ul; i < 0x100; ++i) {
      const auto high = static_cast<ULONG_PTR>(entries[i].OffsetHigh) << 32;
      const auto middle = static_cast<ULONG_PTR>(entries[i].OffsetMiddle) << 16;
      const auto low = static_cast<ULONG_PTR>(entries[i].OffsetLow);
      const auto handler = (high | middle | low);

      g_handlers[i] = reinterpret_cast<void*>(handler);
    }
    g_handlers_initialized = true;
  }

  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  for (auto i = 0ul; i < 0x100; ++i) {
    if (g_handlers[i] == addr) {
      g_handlers_counter[i]++;
      return true;
    }
  }
  return false;
}

static void* RwepFindSourceAddressForExec(void* return_addr) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  const auto current_cr3 = __readcr3();
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  __writecr3(guest_cr3);

  UCHAR code[10] = {};
  auto is_executable = UtilIsExecutableAddress(return_addr);
  if (is_executable) {
    const auto disasseble_addr =
        reinterpret_cast<UCHAR*>(return_addr) - sizeof(code);
    if (PAGE_ALIGN(return_addr) != PAGE_ALIGN(disasseble_addr)) {
      is_executable = UtilIsExecutableAddress(disasseble_addr);
    }
    if (is_executable) {
      RtlCopyMemory(code, disasseble_addr, sizeof(code));
    }
  }

  __writecr3(current_cr3);
  if (!is_executable) {
    return nullptr;
  }

  auto offset = 0ul;
  if (code[5] == 0xe8) {  // e8 xx xx xx xx
    offset = sizeof(code) - 5;
  } else if (code[8] == 0xff) {  // ff xx
    offset = sizeof(code) - 8;
  } else if (code[7] == 0xff) {  // ff xx xx
    offset = sizeof(code) - 7;
  } else if (code[6] == 0xff) {  // ff xx xx xx
    offset = sizeof(code) - 6;
  } else if (code[4] == 0xff) {  // ff xx xx xx xx xx
    offset = sizeof(code) - 4;
  } else if (code[3] == 0xff) {  // ff xx xx xx xx xx xx
    offset = sizeof(code) - 3;
  } else {
    return nullptr;
  }

  if (offset) {
    return reinterpret_cast<UCHAR*>(return_addr) - offset;
  } else {
    return return_addr;
  }
}

_Use_decl_annotations_ static void RwepHandleExecuteViolation(
    ProcessorData* processor_data, void* fault_va) {
  if (RweIsInsideSrcRange(fault_va)) {
    // Someone is entering a source range

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
    void* return_address = nullptr;
    RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));

    const auto fault_base = UtilPcToFileHeader(fault_va);
    const auto is_interrupt = RwepIsInterruptHandler(fault_va);
    const auto src_addr = (is_interrupt)
                              ? return_address
                              : RwepFindSourceAddressForExec(return_address);

    if (!src_addr) {
      HYPERPLATFORM_LOG_DEBUG_SAFE(
          "R= ---------------- (----------------), D= %p (%p), T= E", fault_va,
          fault_base);
    } else if (is_interrupt || src_addr != return_address) {
      const auto src_base = UtilPcToFileHeader(src_addr);
      HYPERPLATFORM_LOG_DEBUG_SAFE("S= %p (%p), D= %p (%p), T= E", src_addr,
                                   src_base, fault_va, fault_base);
    } else {
      const auto return_base = UtilPcToFileHeader(return_address);
      HYPERPLATFORM_LOG_DEBUG_SAFE("R= %p (%p), D= %p (%p), T= E",
                                   return_address, return_base, fault_va,
                                   fault_base);
    }

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
        reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
    void* return_address = nullptr;
    RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));

    // Log only when a return address is inside a source range. By this, we
    // ignore following cases:
    //    - RET from a source range to other range
    //    - conditional and unconditional jump from a source range to other
    //    range
    if (RweIsInsideSrcRange(return_address)) {
      const auto fault_base = UtilPcToFileHeader(fault_va);
      const auto is_interrupt = RwepIsInterruptHandler(fault_va);
      const auto src_addr = (is_interrupt)
                                ? return_address
                                : RwepFindSourceAddressForExec(return_address);

      if (!src_addr) {
        HYPERPLATFORM_LOG_DEBUG_SAFE(
            "R= ---------------- (----------------), D= %p (%p), T= E",
            fault_va, fault_base);
      } else if (is_interrupt || src_addr != return_address) {
        const auto src_base = UtilPcToFileHeader(src_addr);
        HYPERPLATFORM_LOG_INFO_SAFE("S= %p (%p), D= %p (%p), T= E", src_addr,
                                    src_base, fault_va, fault_base);
      } else {
        const auto return_base = UtilPcToFileHeader(return_address);
        HYPERPLATFORM_LOG_INFO_SAFE("R= %p (%p), D= %p (%p), T= E",
                                    return_address, return_base, fault_va,
                                    fault_base);
      }
    }
  }
}

_Use_decl_annotations_ static void RewpSetMonitorTrapFlag(bool enable) {
  VmxProcessorBasedControls vm_procctl = {
      static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl))};
  vm_procctl.fields.monitor_trap_flag = enable;
  UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}

_Use_decl_annotations_ static void RewpSetReadWriteOnPage(
    bool allow_read_write, EptCommonEntry* ept_entry) {
  ept_entry->fields.write_access = allow_read_write;
  ept_entry->fields.read_access = allow_read_write;
  UtilInveptAll();
}

_Use_decl_annotations_ static void* RwepContextCopyMemory(void* destination,
                                                          const void* source,
                                                          SIZE_T length) {
  const auto current_cr3 = __readcr3();
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  __writecr3(guest_cr3);
  const auto result = RtlCopyMemory(destination, source, length);
  __writecr3(current_cr3);
  return result;
}

_Use_decl_annotations_ static void RewpHandleReadWriteViolation(
    ProcessorData* processor_data, void* guest_ip, void* fault_va,
    bool is_write) {
  NT_ASSERT(!processor_data->rwe_data->last_data.ept_entry);

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
      processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));

  // Tempolarily switch to
  //        E   RW
  //  Src   o   o
  //  Dst   x   o
  //  Oth   x   o
  RewpSetReadWriteOnPage(true, ept_entry);
  // HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p",
  //                             PAGE_ALIGN(fault_va));
  RewpSetMonitorTrapFlag(true);

  processor_data->rwe_data->last_data.is_write = is_write;
  processor_data->rwe_data->last_data.guest_ip = guest_ip;
  processor_data->rwe_data->last_data.fault_va = fault_va;
  processor_data->rwe_data->last_data.ept_entry = ept_entry;
  if (is_write) {
    RwepContextCopyMemory(
        processor_data->rwe_data->last_data.old_bytes.data(),
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(fault_va) & ~0xf),
        processor_data->rwe_data->last_data.old_bytes.size());
  } else {
    processor_data->rwe_data->last_data.old_bytes.fill(0);
  }
}

_Use_decl_annotations_ void RweHandleEptViolation(
    ProcessorData* processor_data, void* guest_ip, void* fault_va,
    bool read_violation, bool write_violation, bool execute_violation) {
  if (execute_violation) {
    RwepHandleExecuteViolation(processor_data, fault_va);
  } else if (read_violation || write_violation) {
    RewpHandleReadWriteViolation(processor_data, guest_ip, fault_va,
                                 write_violation);
  } else {
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                   0);
  }
}

_Use_decl_annotations_ static NTSTATUS RwepBytesToString(char* buffer,
                                                         SIZE_T buffer_size,
                                                         const UCHAR* bytes,
                                                         SIZE_T bytes_size) {
  for (auto i = 0ul; i < bytes_size; ++i) {
    const auto consumed_bytes = i * 3;
    const auto remaining_size = buffer_size - consumed_bytes;
    const auto status = RtlStringCchPrintfA(buffer + consumed_bytes,
                                            remaining_size, "%02x ", bytes[i]);
    if (!NT_SUCCESS(status)) {
      NT_ASSERT(false);
      return status;
    }
  }
  buffer[buffer_size - 1] = '\0';
  return STATUS_SUCCESS;
}

_Use_decl_annotations_ void RweHandleMonitorTrapFlag(
    ProcessorData* processor_data) {
  NT_ASSERT(processor_data->rwe_data->last_data.ept_entry);

  // Revert to
  //        E   RW
  //  Src   o   o
  //  Dst   x   x
  //  Oth   x   o
  RewpSetReadWriteOnPage(false, processor_data->rwe_data->last_data.ept_entry);
  // HYPERPLATFORM_LOG_DEBUG_SAFE(
  //    "MONITOR: S:RWE D:--- O:RW- %p",
  //    PAGE_ALIGN(processor_data->rwe_data->last_data.fault_va));
  RewpSetMonitorTrapFlag(false);

  const auto guest_ip_base =
      UtilPcToFileHeader(processor_data->rwe_data->last_data.guest_ip);
  const auto fault_va_base =
      UtilPcToFileHeader(processor_data->rwe_data->last_data.fault_va);

  if (processor_data->rwe_data->last_data.is_write) {
    static const auto kBinaryStringSize =
        kRwepNumOfMonitoredBytesForWrite * 3 + 1;

    UCHAR new_bytes[kRwepNumOfMonitoredBytesForWrite];
    RwepContextCopyMemory(
        new_bytes, reinterpret_cast<void*>(
                       reinterpret_cast<ULONG_PTR>(
                           processor_data->rwe_data->last_data.fault_va) &
                       ~0xf),
        sizeof(new_bytes));

    char new_bytes_string[kBinaryStringSize];
    RwepBytesToString(new_bytes_string, sizeof(new_bytes_string), new_bytes,
                      sizeof(new_bytes));

    char old_bytes_string[kBinaryStringSize];
    RwepBytesToString(old_bytes_string, sizeof(old_bytes_string),
                      processor_data->rwe_data->last_data.old_bytes.data(),
                      processor_data->rwe_data->last_data.old_bytes.size());

    HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= W, %s => %s",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base,
        old_bytes_string, new_bytes_string);

  } else {
    HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= R",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base);
  }
  processor_data->rwe_data->last_data.is_write = false;
  processor_data->rwe_data->last_data.guest_ip = 0;
  processor_data->rwe_data->last_data.fault_va = 0;
  processor_data->rwe_data->last_data.ept_entry = nullptr;
  processor_data->rwe_data->last_data.old_bytes.fill(0);
}

static bool RwepSrcPageCallback(_In_ void* va, _In_ ULONG64 pa,
                                _In_opt_ void* context);
static bool RwepDstPageCallback(_In_ void* va, _In_ ULONG64 pa,
                                _In_opt_ void* context);

// Make source ranges non-executable for normal pages and executable for
// monitor pages
_Use_decl_annotations_ static bool RwepSrcPageCallback(void* va, ULONG64 pa,
                                                       void* context) {
  NT_ASSERT(context);

  if (!pa) {
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);

  const auto ept_entry_n =
      EptGetEptPtEntry(processor_data->ept_data_normal, pa);
  ept_entry_n->fields.execute_access = false;

  const auto ept_entry_m =
      EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
  ept_entry_m->fields.execute_access = true;

  HYPERPLATFORM_LOG_DEBUG_SAFE("NORMAL : S:RW- D:RWE O:RWE %p", PAGE_ALIGN(va));
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:RW- O:RW- %p", PAGE_ALIGN(va));
  return true;
}

// Make dest ranges non-readable/writable/executable for monitor pages
_Use_decl_annotations_ static bool RwepDstPageCallback(void* va, ULONG64 pa,
                                                       void* context) {
  NT_ASSERT(context);

  if (!pa) {
    HYPERPLATFORM_LOG_DEBUG_SAFE("%p is not backed by physical memory.", va);
    return true;
  }

  const auto processor_data = reinterpret_cast<ProcessorData*>(context);
  const auto ept_entry = EptGetEptPtEntry(processor_data->ept_data_monitor, pa);
  ept_entry->fields.execute_access = false;
  ept_entry->fields.write_access = false;
  ept_entry->fields.read_access = false;
  HYPERPLATFORM_LOG_DEBUG_SAFE("MONITOR: S:RWE D:--- O:RW- %p", PAGE_ALIGN(va));
  return true;
}

// Apply ranges to EPT attributes
_Use_decl_annotations_ void RweVmcallApplyRanges(
    ProcessorData* processor_data) {
  NT_ASSERT(processor_data->ept_data == processor_data->ept_data_normal);

  g_rwep_shared_data.src_ranges.for_each_page(RwepSrcPageCallback,
                                              processor_data);
  g_rwep_shared_data.dst_ranges.for_each_page(RwepDstPageCallback,
                                              processor_data);

  UtilInveptAll();
}

_Use_decl_annotations_ void RweHandleTlbFlush(ProcessorData* processor_data) {
  if (g_rwep_shared_data.v2p_map.refresh(processor_data)) {
    RweApplyRangesVmm();
  }
}

_Use_decl_annotations_ void RweApplyRangesVmm() {
  UtilForEachProcessorDpc(RwepApplyRangesDpcRoutine, nullptr);
}

}  // extern "C"
