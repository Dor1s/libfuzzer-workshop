// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

#include <stdint.h>
#include <stddef.h>

#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bool verify_hash_flags[] = { false, true };

  for (auto flag : verify_hash_flags)
    VulnerableFunction2(data, size, flag);
  return 0;
}
