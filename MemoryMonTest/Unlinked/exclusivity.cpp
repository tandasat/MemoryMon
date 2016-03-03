// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements a lock function halts all processors but the current
// one, and corresponding a release function. The lock function is also known
// as GainExclusivity.
//
#include "exclusivity.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Tag used for memory allocation APIs
static const ULONG kExclpPoolTag = 'excl';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct ExclusivityContext {
  union {
    KIRQL old_irql;
    void *reserved;
  };
  KDPC dpcs[1];  // This field is used as a variadic array
};
static_assert(sizeof(ExclusivityContext) == sizeof(void *) + sizeof(KDPC),
              "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static KDEFERRED_ROUTINE ExclpRaiseIrqlAndWaitDpc;

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// 1 when all processors should be released; otherwise 0.
static volatile LONG g_exclp_release_all_processors = 0;

// How many processors were locked.
static volatile LONG g_exclp_number_of_locked_processors = 0;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Locks all other processors and returns exclusivity pointer. This function
// should never be called before the last exclusivity is released.
_Use_decl_annotations_ void *ExclGainExclusivity() {
  NT_ASSERT(InterlockedAdd(&g_exclp_number_of_locked_processors, 0) == 0);
  InterlockedAnd(&g_exclp_release_all_processors, 0);

  const auto number_of_processors = KeQueryActiveProcessorCount(nullptr);

  // Allocates DPCs for all processors.
  const auto context =
      reinterpret_cast<ExclusivityContext *>(ExAllocatePoolWithTag(
          NonPagedPoolNx,
          sizeof(void *) + (number_of_processors * sizeof(KDPC)),
          kExclpPoolTag));
  if (!context) {
    return nullptr;
  }

  // Execute a lock DPC for all processors but this.
  context->old_irql = KeRaiseIrqlToDpcLevel();
  const auto current_processor = KeGetCurrentProcessorNumber();
  for (auto i = 0ul; i < number_of_processors; i++) {
    if (i == current_processor) {
      continue;
    }

    // Queue a lock DPC.
    KeInitializeDpc(&context->dpcs[i], ExclpRaiseIrqlAndWaitDpc, nullptr);
    KeSetTargetProcessorDpc(&context->dpcs[i], static_cast<CCHAR>(i));
    KeInsertQueueDpc(&context->dpcs[i], nullptr, nullptr);
  }

  // Wait until all other processors were halted.
  const LONG need_to_be_locked = number_of_processors - 1;
  while (_InterlockedCompareExchange(&g_exclp_number_of_locked_processors,
                                     need_to_be_locked,
                                     need_to_be_locked) != need_to_be_locked) {
    KeStallExecutionProcessor(10);
  }
  return context;
}

#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ void ExclReleaseExclusivity(void *exclusivity) {
  if (!exclusivity) {
    return;
  }

  // Tell other processors they can be unlocked with changing the value.
  _InterlockedIncrement(&g_exclp_release_all_processors);

  // Wait until all other processors were unlocked.
  while (
      _InterlockedCompareExchange(&g_exclp_number_of_locked_processors, 0, 0)) {
    KeStallExecutionProcessor(10);
  }

  const auto context = static_cast<ExclusivityContext *>(exclusivity);
  KeLowerIrql(context->old_irql);
  ExFreePoolWithTag(exclusivity, kExclpPoolTag);
}

// Locks this processor until g_ReleaseAllProcessors becomes 1.
_Use_decl_annotations_ static void ExclpRaiseIrqlAndWaitDpc(
    PKDPC dpc, PVOID deferred_context, PVOID system_argument1,
    PVOID system_argument2) {
  UNREFERENCED_PARAMETER(dpc);
  UNREFERENCED_PARAMETER(deferred_context);
  UNREFERENCED_PARAMETER(system_argument1);
  UNREFERENCED_PARAMETER(system_argument2);

  // Increase the number of locked processors.
  _InterlockedIncrement(&g_exclp_number_of_locked_processors);

  // Wait until g_ReleaseAllProcessors becomes 1.
  while (!_InterlockedCompareExchange(&g_exclp_release_all_processors, 1, 1)) {
    KeStallExecutionProcessor(10);
  }

  // Decrease the number of locked processors.
  _InterlockedDecrement(&g_exclp_number_of_locked_processors);
}
#pragma warning(pop)

}  // extern "C"
