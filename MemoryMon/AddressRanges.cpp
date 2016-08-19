// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements the AddressRanges class.

#include "AddressRanges.h"
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"

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

/*_Use_decl_annotations_*/ AddressRanges::AddressRanges() {
  KeInitializeSpinLock(&ranges_spinlock_);
}

_Use_decl_annotations_ void AddressRanges::add(void* address, SIZE_T size) {
  const auto end_address =
      reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(address) + size - 1);
  ranges_.push_back(AddressRangeEntry{address, end_address});
}

_Use_decl_annotations_ bool AddressRanges::is_in_range(void* address) const {
  bool inside = false;
  for (const auto& range : ranges_) {
    if (UtilIsInBounds(address, range.start_address, range.end_address)) {
      inside = true;
      break;
    }
  }
  return inside;
}

_Use_decl_annotations_ void AddressRanges::for_each_page(
    ForEachCallback callback, void* context) {
  for (const auto& range : ranges_) {
    const auto start_address = reinterpret_cast<ULONG_PTR>(range.start_address);
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
