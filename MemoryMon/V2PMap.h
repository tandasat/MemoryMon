// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to the V2PMap2 class.

#ifndef MEMORYMON_V2PMAP_H_
#define MEMORYMON_V2PMAP_H_

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

struct ProcessorData;

class V2PMap2 {
 public:
  V2PMap2();
  void add(_In_ void* address, _In_ SIZE_T size);
  bool refresh(_In_ ProcessorData* processor_data);

 private:
  struct V2PMapEntry {
    void* va;
    ULONG64 pa;
  };

  std::vector<V2PMapEntry> v2p_map_;
  mutable KSPIN_LOCK v2p_map_spinlock_;
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

#endif  // MEMORYMON_V2PMAP_H_
