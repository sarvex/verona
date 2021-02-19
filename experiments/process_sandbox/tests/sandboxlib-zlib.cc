// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#include "sandbox.hh"
#include "shared.h"

extern "C" void sandbox_init(sandbox::ExportedLibrary* library)
{
#define EXPORTED_FUNCTION(x, name) library->export_function(name);
#include "zlib.inc"
}
