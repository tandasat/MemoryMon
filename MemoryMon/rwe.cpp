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
#include "V2PMap.h"
#include "AddressRanges.h"
#include <array>
#include <capstone.h>

// unreferenced local function has been removed
#pragma warning(disable : 4505)

#if !defined(_AMD64_)
#error This project does not support x86 yet.
#endif

extern "C" {
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

struct RweLastData {
  bool is_write;
  void* guest_ip;
  void* fault_va;
  EptCommonEntry* ept_entry;
  std::array<UCHAR, kRwepNumOfMonitoredBytesForWrite> old_bytes;

  RweLastData()
      : is_write(false), guest_ip(0), fault_va(0), ept_entry(nullptr) {}
};

struct RweData {
  RweLastData last_data;
};

struct RweSharedData {
  AddressRanges src_ranges;
  AddressRanges dst_ranges;
  V2PMap2 v2p_map;
  bool applied;
};

// dt nt!_kIDTENTRY64
struct IDTENTRY64 {
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
};
static_assert(sizeof(IDTENTRY64) == 0x10, "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static KDEFERRED_ROUTINE RwepApplyRangesDpcRoutine;

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

static bool RwepSrcPageCallback(_In_ void* va, _In_ ULONG64 pa,
                                _In_opt_ void* context);

static bool RwepDstPageCallback(_In_ void* va, _In_ ULONG64 pa,
                                _In_opt_ void* context);

static void* RwepFindSourceAddressForExec(_In_ void* return_addr);

_Success_(return ) static bool RwepGetValueFromRegister(
    _Inout_ GpRegisters* gp_regs, _In_ x86_reg reg, _Out_ ULONG64* value);

_Success_(return ) static bool RwepGetMmIoValue(_In_ void* address,
                                                _In_ GpRegisters* gp_regs,
                                                _In_ bool is_write,
                                                _Out_ ULONG64* value,
                                                _Out_ SIZE_T* size);

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

static RweSharedData g_rwep_shared_data;

struct InterruptHandlers {
  struct InterruptHandlerEntry {
    void* handler;
    volatile LONG64 hit_counter;
  };

  std::array<InterruptHandlerEntry, 0xff> handlers;

  InterruptHandlers() {
    Idtr idtr = {};
    __sidt(&idtr);

    const auto entries = reinterpret_cast<IDTENTRY64*>(idtr.base);
    NT_ASSERT(entries);

    for (auto i = 0ul; i < handlers.size(); ++i) {
      const auto high = static_cast<ULONG_PTR>(entries[i].OffsetHigh) << 32;
      const auto middle = static_cast<ULONG_PTR>(entries[i].OffsetMiddle) << 16;
      const auto low = static_cast<ULONG_PTR>(entries[i].OffsetLow);
      const auto handler = (high | middle | low);

      handlers[i].handler = reinterpret_cast<void*>(handler);
    }
  }

  bool has(void* addr) {
    for (auto& handler : handlers) {
      if (handler.handler == addr) {
        InterlockedIncrement64(&handler.hit_counter);
        return true;
      }
    }
    return false;
  }
};
static InterruptHandlers g_rewp_int_handlers;

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
  const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add SRC range: %p - %p", address, end_address);
  g_rwep_shared_data.src_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
}

_Use_decl_annotations_ void RweAddDstRange(void* address, SIZE_T size) {
  const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  HYPERPLATFORM_LOG_DEBUG_SAFE("Add DST range: %p - %p", address, end_address);
  g_rwep_shared_data.dst_ranges.add(address, size);
  g_rwep_shared_data.v2p_map.add(address, size);
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

// Set a va associated with 0xfd5fa000 as a dest range
_Use_decl_annotations_ void RweHandleNewDeviceMemoryAccess(ULONG64 pa,
                                                           void* va) {
#if defined(MEMORYMON_ENABLE_MMIO_TRACE)
  if (reinterpret_cast<ULONG64>(PAGE_ALIGN(pa)) == 0xfd5fa000) {
    RweAddDstRange(PAGE_ALIGN(va), PAGE_SIZE);
  }
#endif
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

_Use_decl_annotations_ static void* RwepFindSourceAddressForExec(
    void* return_addr) {
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

#if !defined(MEMORYMON_ENABLE_MMIO_TRACE)
    const auto guest_sp =
        reinterpret_cast<void**>(UtilVmRead(VmcsField::kGuestRsp));
    void* return_address = nullptr;
    RwepContextCopyMemory(&return_address, guest_sp, sizeof(void*));

    const auto fault_base = UtilPcToFileHeader(fault_va);
    const auto is_interrupt = g_rewp_int_handlers.has(fault_va);
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
#endif  // !defined(MEMORYMON_ENABLE_MMIO_TRACE)

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

#if !defined(MEMORYMON_ENABLE_MMIO_TRACE)
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
      const auto is_interrupt = g_rewp_int_handlers.has(fault_va);
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
#endif  // defined(MEMORYMON_ENABLE_MMIO_TRACE)
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

  // most of cases. if the operation happed just outside, may be not
  NT_ASSERT(RweIsInsideDstRange(fault_va));

  const auto ept_entry = EptGetEptPtEntry(
      processor_data->ept_data, UtilVmRead64(VmcsField::kGuestPhysicalAddress));

  // Temporarily switch to
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
#if !defined(MEMORYMON_ENABLE_MMIO_TRACE)
    RwepContextCopyMemory(
        processor_data->rwe_data->last_data.old_bytes.data(),
        reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(fault_va) & ~0xf),
        processor_data->rwe_data->last_data.old_bytes.size());
#endif
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

_Use_decl_annotations_ static bool RwepGetValueFromRegister(
    GpRegisters* gp_regs, x86_reg reg, ULONG64* value) {
  // Covers registers that are likely to be used. It is not comprehensive and
  // does not includes all possible registers.
  ULONG64 val = 0;
  switch (reg) {
    // clang-format off
    case X86_REG_AL:  val = gp_regs->ax & UINT8_MAX; break;
    case X86_REG_AH:  val = (gp_regs->ax >> 8) & UINT8_MAX; break;
    case X86_REG_AX:  val = gp_regs->ax & UINT16_MAX; break;
    case X86_REG_EAX: val = gp_regs->ax & UINT32_MAX; break;
    case X86_REG_RAX: val = gp_regs->ax; break;

    case X86_REG_BL:  val = gp_regs->bx & UINT8_MAX; break;
    case X86_REG_BH:  val = (gp_regs->bx >> 8) & UINT8_MAX; break;
    case X86_REG_BX:  val = gp_regs->bx & UINT16_MAX; break;
    case X86_REG_EBX: val = gp_regs->bx & UINT32_MAX; break;
    case X86_REG_RBX: val = gp_regs->bx; break;

    case X86_REG_CL:  val = gp_regs->cx & UINT8_MAX; break;
    case X86_REG_CH:  val = (gp_regs->cx >> 8) & UINT8_MAX; break;
    case X86_REG_CX:  val = gp_regs->cx & UINT16_MAX; break;
    case X86_REG_ECX: val = gp_regs->cx & UINT32_MAX; break;
    case X86_REG_RCX: val = gp_regs->cx; break;

    case X86_REG_DL:  val = gp_regs->dx & UINT8_MAX; break;
    case X86_REG_DH:  val = (gp_regs->dx >> 8) & UINT8_MAX; break;
    case X86_REG_DX:  val = gp_regs->dx & UINT16_MAX; break;
    case X86_REG_EDX: val = gp_regs->dx & UINT32_MAX; break;
    case X86_REG_RDX: val = gp_regs->dx; break;

    case X86_REG_DIL: val = gp_regs->di & UINT8_MAX; break;
    case X86_REG_DI:  val = gp_regs->di & UINT16_MAX; break;
    case X86_REG_EDI: val = gp_regs->di & UINT32_MAX; break;
    case X86_REG_RDI: val = gp_regs->di; break;

    case X86_REG_SIL: val = gp_regs->si & UINT8_MAX; break;
    case X86_REG_SI:  val = gp_regs->si & UINT16_MAX; break;
    case X86_REG_ESI: val = gp_regs->si & UINT32_MAX; break;
    case X86_REG_RSI: val = gp_regs->si; break;

    case X86_REG_BPL: val = gp_regs->r15 & UINT8_MAX; break;
    case X86_REG_BP:  val = gp_regs->r15 & UINT16_MAX; break;
    case X86_REG_EBP: val = gp_regs->r15 & UINT32_MAX; break;
    case X86_REG_RBP: val = gp_regs->r15; break;

    case X86_REG_R8B: val = gp_regs->r8 & UINT8_MAX; break;
    case X86_REG_R8W: val = gp_regs->r8 & UINT16_MAX; break;
    case X86_REG_R8D: val = gp_regs->r8 & UINT32_MAX; break;
    case X86_REG_R8:  val = gp_regs->r8; break;

    case X86_REG_R9B: val = gp_regs->r9 & UINT8_MAX; break;
    case X86_REG_R9W: val = gp_regs->r9 & UINT16_MAX; break;
    case X86_REG_R9D: val = gp_regs->r9 & UINT32_MAX; break;
    case X86_REG_R9:  val = gp_regs->r9; break;

    case X86_REG_R10B: val = gp_regs->r10 & UINT8_MAX; break;
    case X86_REG_R10W: val = gp_regs->r10 & UINT16_MAX; break;
    case X86_REG_R10D: val = gp_regs->r10 & UINT32_MAX; break;
    case X86_REG_R10:  val = gp_regs->r10; break;

    case X86_REG_R11B: val = gp_regs->r11 & UINT8_MAX; break;
    case X86_REG_R11W: val = gp_regs->r11 & UINT16_MAX; break;
    case X86_REG_R11D: val = gp_regs->r11 & UINT32_MAX; break;
    case X86_REG_R11:  val = gp_regs->r11; break;

    case X86_REG_R12B: val = gp_regs->r12 & UINT8_MAX; break;
    case X86_REG_R12W: val = gp_regs->r12 & UINT16_MAX; break;
    case X86_REG_R12D: val = gp_regs->r12 & UINT32_MAX; break;
    case X86_REG_R12:  val = gp_regs->r12; break;

    case X86_REG_R13B: val = gp_regs->r13 & UINT8_MAX; break;
    case X86_REG_R13W: val = gp_regs->r13 & UINT16_MAX; break;
    case X86_REG_R13D: val = gp_regs->r13 & UINT32_MAX; break;
    case X86_REG_R13:  val = gp_regs->r13; break;

    case X86_REG_R14B: val = gp_regs->r14 & UINT8_MAX; break;
    case X86_REG_R14W: val = gp_regs->r14 & UINT16_MAX; break;
    case X86_REG_R14D: val = gp_regs->r14 & UINT32_MAX; break;
    case X86_REG_R14:  val = gp_regs->r14; break;

    case X86_REG_R15B: val = gp_regs->r15 & UINT8_MAX; break;
    case X86_REG_R15W: val = gp_regs->r15 & UINT16_MAX; break;
    case X86_REG_R15D: val = gp_regs->r15 & UINT32_MAX; break;
    case X86_REG_R15:  val = gp_regs->r15; break;
    // clang-format on

    default:
      return false;
  }

  *value = val;
  return true;
}

_Use_decl_annotations_ static bool RwepGetMmIoValue(void* address,
                                                    GpRegisters* gp_regs,
                                                    bool is_write,
                                                    ULONG64* value,
                                                    SIZE_T* size) {
  bool result = false;

  // NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  csh handle = {};
  if (cs_open(CS_ARCH_X86, (sizeof(void*) == 4) ? CS_MODE_32 : CS_MODE_64,
              &handle) != CS_ERR_OK) {
    return result;
  }

  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    cs_close(&handle);
    return result;
  }

  const auto current_cr3 = __readcr3();
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  __writecr3(guest_cr3);

  cs_insn* instructions = {};
  auto count = cs_disasm(handle, (uint8_t*)address, 15, (uint64_t)address, 0,
                         &instructions);

  __writecr3(current_cr3);
  if (count == 0) {
    cs_close(&handle);
    return result;
  }

  const auto& inst = instructions[0];
  HYPERPLATFORM_LOG_DEBUG_SAFE("%s %s", inst.mnemonic, inst.op_str);

  if (is_write) {
    switch (inst.id) {
      case X86_INS_MOV:
      case X86_INS_STOSB:
      case X86_INS_STOSD:
      case X86_INS_STOSQ:
      case X86_INS_STOSW:
        break;
      default:
        goto exit;
    }

    if (inst.detail->x86.op_count != 2) {
      goto exit;
    }

    const auto& second_operand = inst.detail->x86.operands[1];
    if (second_operand.type == X86_OP_REG &&
        RwepGetValueFromRegister(gp_regs, second_operand.reg, value)) {
      *size = second_operand.size;
    } else if (second_operand.type == X86_OP_IMM) {
      *value = second_operand.imm;
      *size = second_operand.size;
    } else {
      goto exit;
    }
  } else {
    switch (inst.id) {
      case X86_INS_MOV:
        break;
      default:
        goto exit;
    }

    if (inst.detail->x86.op_count != 2) {
      goto exit;
    }

    const auto& first_operand = inst.detail->x86.operands[0];
    if (first_operand.type == X86_OP_REG &&
        RwepGetValueFromRegister(gp_regs, first_operand.reg, value)) {
      *size = first_operand.size;
    } else {
      goto exit;
    }
  }

  result = true;

exit:;
  cs_free(instructions, count);
  cs_close(&handle);
  return result;
}

_Use_decl_annotations_ void RweHandleMonitorTrapFlag(
    ProcessorData* processor_data, GpRegisters* gp_regs) {
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
#if !defined(MEMORYMON_ENABLE_MMIO_TRACE)
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
#else
    HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= W",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base);
#endif)
  } else {
    HYPERPLATFORM_LOG_INFO_SAFE(
        "S= %p (%p), D= %p (%p), T= R",
        processor_data->rwe_data->last_data.guest_ip, guest_ip_base,
        processor_data->rwe_data->last_data.fault_va, fault_va_base);
  }

#if defined(MEMORYMON_ENABLE_MMIO_TRACE)
  ULONG64 value = 0;
  SIZE_T size = 0;
  if (RwepGetMmIoValue(processor_data->rwe_data->last_data.guest_ip, gp_regs,
                       processor_data->rwe_data->last_data.is_write, &value,
                       &size)) {
    // clang-format off
    switch (size) {
    case 1: HYPERPLATFORM_LOG_INFO_SAFE("Value= %02x", value & UINT8_MAX); break;
    case 2: HYPERPLATFORM_LOG_INFO_SAFE("Value= %04x", value & UINT16_MAX); break;
    case 4: HYPERPLATFORM_LOG_INFO_SAFE("Value= %08x", value & UINT32_MAX); break;
    case 8: HYPERPLATFORM_LOG_INFO_SAFE("Value= %016llx", value); break;
    default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
    }
    // clang-format on
  } else {
    // Failed to get value. Most likely due to unsupported instruction
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
#endif  // defined(MEMORYMON_ENABLE_MMIO_TRACE

  processor_data->rwe_data->last_data.is_write = false;
  processor_data->rwe_data->last_data.guest_ip = 0;
  processor_data->rwe_data->last_data.fault_va = 0;
  processor_data->rwe_data->last_data.ept_entry = nullptr;
  processor_data->rwe_data->last_data.old_bytes.fill(0);
}

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
  g_rwep_shared_data.applied = true;
  UtilInveptAll();
}

_Use_decl_annotations_ void RweHandleTlbFlush(ProcessorData* processor_data) {
  if (g_rwep_shared_data.v2p_map.refresh(processor_data)) {
    UtilForEachProcessorDpc(RwepApplyRangesDpcRoutine, nullptr);
  }
}

}  // extern "C"
