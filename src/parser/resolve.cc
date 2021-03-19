// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#include "resolve.h"

#include "ident.h"
#include "lookup.h"
#include "rewrite.h"

namespace verona::parser::resolve
{
  struct Resolve : Pass<Resolve>
  {
    AST_PASS;

    Ident ident;
    Location name_create;

    Resolve()
    {
      name_create = ident("create");
    }

    void post(TypeRef& tr)
    {
      // This checks that the type exists but doesn't rewrite the AST.
      bool from_using = (parent()->kind() == Kind::Using);
      auto paths = look_up(stack, tr.typenames, from_using);

      if (paths.empty())
      {
        error() << tr.location << "Couldn't find a definition of this type."
                << text(tr.location);
        return;
      }

      if (paths.size() > 1)
      {
        auto& out = error()
          << tr.location << "Found multiple definitions of this type."
          << text(tr.location);

        for (auto& path : paths)
        {
          auto& loc = path.back()->location;
          out << loc << "Found a definition here." << text(loc);
        }
        return;
      }

      auto& def = paths.front().back();

      if (!is_kind(
            def,
            {Kind::Class, Kind::Interface, Kind::TypeAlias, Kind::TypeParam}))
      {
        error() << tr.location << "Expected a type, but got a "
                << kindname(def->kind()) << text(tr.location) << def->location
                << "Definition is here" << text(def->location);
      }
    }

    void post(Select& select)
    {
      // If it's a single element name with a left-hand side, it will be
      // treated as a member selection.
      if ((select.expr || select.args) && (select.typenames.size() == 1))
        return;

      // Find all definitions of the selector.
      auto paths = look_up(stack, select.typenames);

      if (paths.empty())
      {
        error() << select.typenames.front()->location
                << "Couldn't find a definition for this."
                << text(select.typenames.front()->location);
        return;
      }

      if (paths.size() > 1)
      {
        auto& out = error() << select.typenames.front()->location
                            << "Found multiple definitions of this."
                            << text(select.typenames.front()->location);

        for (auto& path : paths)
        {
          auto& loc = path.back()->location;
          out << loc << "Found a definition here." << text(loc);
        }
        return;
      }

      auto& def = paths.front().back();

      if (is_kind(def, {Kind::Class, Kind::Interface, Kind::TypeAlias}))
      {
        // We found a type as a selector, so we'll turn it into a constructor.
        auto create = std::make_shared<TypeName>();
        create->location = name_create;
        select.typenames.push_back(create);
      }
      else if (!is_kind(def, {Kind::Function}))
      {
        error() << select.typenames.front()->location
                << "Expected a type or function, but got a "
                << kindname(def->kind())
                << text(select.typenames.front()->location) << def->location
                << "Definition is here" << text(def->location);
      }
    }

    void post(Tuple& tuple)
    {
      // TODO: delete if size = 0 ?
      // Collapse unnecessary tuple nodes.
      if (tuple.seq.size() != 1)
        return;

      rewrite(stack, tuple.seq.front());
    }
  };

  bool run(Ast& ast, std::ostream& out)
  {
    Resolve r;
    r.set_error(out);
    return r << ast;
  }

  struct WF : Pass<WF>
  {
    AST_PASS;
  };

  bool wellformed(Ast& ast, std::ostream& out)
  {
    WF wf;
    wf.set_error(out);
    return wf << ast;
  }
}