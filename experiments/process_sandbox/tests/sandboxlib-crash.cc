// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#include "sandbox.hh"
#include "shared.h"

int crash()
{
  abort();
}

extern "C" void sandbox_init(sandbox::ExportedLibrary* library)
{
  library->export_function(::crash);
}
