// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements the PageFaultRecord class.

#include "PageFaultRecord.h"
#include <algorithm>
#include "ScopedLock.h"

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

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

/*_Use_decl_annotations_*/ PageFaultRecord::PageFaultRecord() {
  KeInitializeSpinLock(&record_spinlock_);
}

_Use_decl_annotations_ void PageFaultRecord::push(PETHREAD thread,
                                                  void* guest_ip) {
  ScopedLock lock(&record_spinlock_);
  record_.push_back(PageFaultRecordEntry{thread, guest_ip});
}

_Use_decl_annotations_ bool PageFaultRecord::has(PETHREAD thread) const {
  ScopedLock lock(&record_spinlock_);
  const auto position = std::find_if(
      record_.begin(), record_.end(),
      [thread](const auto& elem) { return elem.thread == thread; });
  return (position != record_.end());
}

_Use_decl_annotations_ void* PageFaultRecord::pop(PETHREAD thread) {
  ScopedLock lock(&record_spinlock_);
  const auto position = std::find_if(
      record_.begin(), record_.end(),
      [thread](const auto& elem) { return elem.thread == thread; });
  if (position == record_.end()) {
    return nullptr;
  }
  const auto guest_ip = position->guest_ip;
  record_.erase(position);
  return guest_ip;
}
