// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to the V2PMap2 class.

#ifndef MEMORYMON_ADDRESSRANGES_H_
#define MEMORYMON_ADDRESSRANGES_H_

#include <fltKernel.h>
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <vector>

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

class AddressRanges {
 public:
  using ForEachCallback = bool (*)(_In_ void* va, _In_ ULONG64 pa,
                                   _In_opt_ void* context);

  AddressRanges();
  void add(_In_ void* address, _In_ SIZE_T size);
  bool is_in_range(_In_ void* address) const;
  void for_each_page(_In_ ForEachCallback callback, _In_opt_ void* context);

 private:
  struct AddressRangeEntry {
    void* start_address;  // inclusive
    void* end_address;    // inclusive
  };
  std::vector<AddressRangeEntry> ranges_;
  mutable KSPIN_LOCK ranges_spinlock_;
};

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

#endif  // MEMORYMON_ADDRESSRANGES_H_
