#!/usr/bin/env python3
"""Generate the CONTRACT §27 management surface for the C++ SDK.

Reads ``management-registry.json`` (the 146 operations across 24 namespaces,
maintained in ``ilpanich/axiam`` and vendored here) plus ``openapi.json``, and writes:

- ``include/axiam/management_models.hpp`` — one struct or enum per request and response
  type, with ``from_json``/``to_json`` free functions ADL-found by nlohmann;
- ``include/axiam/management.hpp`` — the 24 namespace handles and the ``management()``
  accessor;
- ``src/management_models.cpp`` / ``src/management_ops.cpp`` — the implementations;
- ``tests/test_management_generated.cpp`` — one conformance case per operation.

Run with ``--check`` to verify the committed output is current; that is what CI runs.

**C++ gets namespace HANDLES, not C's flat symbols.** §27.3's per-language table is
explicit — its C++ row reads ``client.service_accounts().rotate_secret(id)`` — and the
sentence beneath it grants the flat accommodation to C alone ("C has no handle to hang
operations on"). C++ has one, so it uses it.

The two languages otherwise share a shape, and the difference is worth naming: C's
optional fields need a companion ``has_`` flag because a ``long`` cannot represent
"absent", while here ``std::optional<T>`` says it directly; C needs a ``_free()`` per
model, while here the destructor is the compiler's problem.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY: dict[str, Any] = json.loads((ROOT / "management-registry.json").read_text())
SPEC: dict[str, Any] = json.loads((ROOT / "openapi.json").read_text())
SCHEMAS: dict[str, Any] = SPEC["components"]["schemas"]

# §27.4 rule 3: `{org_id}` always defaults from the client. `{tenant_id}`
# defaults from the client only where it names the *context*; in `tenants` and
# the signing-CA routes it names the object being acted on.
IMPLICIT_TENANT_NAMESPACES = {"email_config", "settings", "webauthn_policy"}

# Schema names that would collide with a type this SDK already declares. The models sit
# in `axiam::management` alongside the hand-written core, so a collision is possible --
# `Scope` was one, and is why `CallScope` is spelled the way it is. RESERVED_TYPES in
# model_type() turns a future collision into a build failure rather than a silent
# redefinition; this map is where the rename goes when one happens.
RENAMED_SCHEMAS: dict[str, str] = {}

EXAMPLE_UUID = "11111111-1111-4111-8111-111111111111"

# Deliberately different from EXAMPLE_UUID and from the fixture client's own scope, so a
# §27.4 rule 3 assertion can tell an override that took effect from one that was ignored.
OTHER_ORG = "22222222-2222-4222-8222-222222222222"
OTHER_TENANT = "33333333-3333-4333-8333-333333333333"
EXAMPLE_TIME = "2026-08-26T00:00:00Z"


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


def pascal(text: str) -> str:
    """``service_accounts`` -> ``ServiceAccounts``; already-Pascal input is kept.

    Deliberately does NOT normalise initialisms, so every generated type name can be
    grepped straight out of ``openapi.json``.
    """
    if "_" not in text and "-" not in text and text[:1].isupper():
        return RENAMED_SCHEMAS.get(text, text)
    parts = [p for p in text.replace("-", "_").replace(" ", "_").split("_") if p]
    joined = "".join(p[0].upper() + p[1:] for p in parts)
    return RENAMED_SCHEMAS.get(joined, joined)


def camel(text: str) -> str:
    """``service_accounts`` -> ``serviceAccounts``; the PHP property spelling."""
    out = pascal(text)
    return out[0].lower() + out[1:] if out else out


# PHP reserved words that cannot be used bare as a method name on a class.
# (Property names are far less restricted, but methods share the keyword space.)
PHP_KEYWORDS = {
    "abstract", "and", "array", "as", "break", "callable", "case", "catch",
    "class", "clone", "const", "continue", "declare", "default", "do", "echo",
    "else", "elseif", "empty", "enddeclare", "endfor", "endforeach", "endif",
    "endswitch", "endwhile", "enum", "eval", "exit", "extends", "final",
    "finally", "fn", "for", "foreach", "function", "global", "goto", "if",
    "implements", "include", "instanceof", "insteadof", "interface", "isset",
    "list", "match", "namespace", "new", "or", "print", "private", "protected",
    "public", "readonly", "require", "return", "static", "switch", "throw",
    "trait", "try", "unset", "use", "var", "while", "xor", "yield",
}


def prop(name: str) -> str:
    """A PHP property name for a wire field. Properties may be keywords; methods may not."""
    return camel(name)


def method(name: str) -> str:
    """A PHP-legal method name for ``name``.

    ``list`` is a language construct and cannot be a bare method name in the PHP
    versions this SDK supports, and it is also the single most common §27 operation
    name -- so the suffix rule earns its keep on the very first namespace.
    """
    ident = camel(name)
    return f"{ident}Items" if ident.lower() in PHP_KEYWORDS else ident


def snake(text: str) -> str:
    """``ServiceAccounts`` -> ``service_accounts``; already-snake input is kept."""
    out: list[str] = []
    for i, ch in enumerate(text):
        boundary = not text[i - 1].isupper() or (i + 1 < len(text) and text[i + 1].islower())
        if ch.isupper() and i and boundary:
            out.append("_")
        out.append(ch.lower())
    return "".join(out).replace("-", "_").replace("__", "_")


def wrap(text: str, width: int = 76) -> list[str]:
    """Reflow ``text`` into paragraph-preserving lines."""
    out: list[str] = []
    for para in str(text).strip().split("\n\n"):
        words = para.split()
        if not words:
            continue
        line = ""
        for word in words:
            if line and len(line) + 1 + len(word) > width:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}" if line else word
        if line:
            out.append(line)
        out.append("")
    while out and out[-1] == "":
        out.pop()
    return out


def escape(text: str) -> str:
    """Make an ``openapi.json`` description safe to paste into a PHP docblock.

    A docblock is delimited by ``*/``, so a description containing one would close the
    comment early and spill the rest into code -- the PHP analogue of the nested-KDoc
    bug the Kotlin port hit. Both ``*/`` and ``/*`` are neutralised.
    """
    out = " ".join(str(text).split())
    return out.replace("*/", "* /").replace("/*", "/ *")


def docblock(text: str, indent: str = "", tags: list[str] | None = None) -> list[str]:
    """A wrapped docblock at ``indent``, with optional trailing ``@``-tag lines."""
    paragraphs = [p for p in str(text).split("\n\n") if p.strip()]
    width = 92 - len(indent)
    out = [f"{indent}/**"]
    first = True
    for para in paragraphs or [""]:
        if not first:
            out.append(f"{indent} *")
        for line in wrap(para, width):
            out.append(f"{indent} * {line}".rstrip())
        first = False
    for tag in tags or []:
        lines = wrap(tag, width)
        out.append(f"{indent} * {lines[0]}")
        out.extend(f"{indent} *     {more}" for more in lines[1:])
    out.append(f"{indent} */")
    return out


def inline_doc(text: str, indent: str = "") -> list[str]:
    """A one-line docblock, or a wrapped block when it will not fit."""
    single = f"{indent}/** {text} */"
    if len(single) <= 100 and "\n" not in text:
        return [single]
    return docblock(text, indent)


def resolve_ref(schema: Any) -> Any:
    """Follow ``$ref`` chains to the schema they name."""
    node = schema
    while isinstance(node, dict) and "$ref" in node:
        node = SCHEMAS.get(node["$ref"].split("/")[-1], {})
    return node


def nullable_ref(schema: Any) -> str | None:
    """``{oneOf: [{type: null}, {$ref: X}]}`` -- utoipa's optional-enum shape."""
    variants = schema.get("oneOf") if isinstance(schema, dict) else None
    if not isinstance(variants, list) or len(variants) != 2:
        return None
    nulls = [v for v in variants if v.get("type") == "null"]
    refs = [v for v in variants if "$ref" in v]
    return refs[0]["$ref"].split("/")[-1] if len(nulls) == 1 and len(refs) == 1 else None


def flatten(name: str) -> tuple[dict[str, Any], set[str], str | None]:
    """Properties, required set and description of ``name``, ``allOf`` resolved."""
    props: dict[str, Any] = {}
    required: set[str] = set()

    def absorb(node: Any) -> None:
        """Merge one ``allOf`` member's properties into the accumulator."""
        resolved = resolve_ref(node) if "$ref" in node else node
        props.update(resolved.get("properties") or {})
        required.update(resolved.get("required") or [])
        for sub in resolved.get("allOf") or []:
            absorb(sub)

    schema = SCHEMAS.get(name, {})
    absorb(schema)
    return props, required, schema.get("description")


def discriminated(schema: Any) -> tuple[str, list[tuple[str, Any]]] | None:
    """Detect an internally-tagged union and return ``(tag, [(value, payload)])``."""
    variants = schema.get("oneOf")
    if not isinstance(variants, list) or len(variants) < 2:
        return None
    tag: str | None = None
    arms: list[tuple[str, Any]] = []
    for variant in variants:
        parts = variant.get("allOf") or [variant]
        value: str | None = None
        payload: Any = None
        leftovers: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in parts:
            if "$ref" in part:
                payload = part
                continue
            for pname, pschema in (part.get("properties") or {}).items():
                enum = pschema.get("enum")
                if pschema.get("type") == "string" and isinstance(enum, list) and len(enum) == 1:
                    if tag and tag != pname:
                        return None
                    tag = pname
                    value = enum[0]
                else:
                    leftovers["properties"][pname] = pschema
                    if pname in (part.get("required") or []):
                        leftovers["required"].append(pname)
        if value is None:
            return None
        arms.append((value, payload if payload is not None else leftovers))
    return (tag or "", arms)


def sensitive_map() -> dict[str, set[str]]:
    """Which fields of which schemas carry a secret, per the registry."""
    out: dict[str, set[str]] = {}
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            if op["request_schema"] and op["sensitive_request_fields"]:
                key = op["request_schema"].lstrip("[]")
                out.setdefault(key, set()).update(op["sensitive_request_fields"])
            if op["response"]["schema"] and op["sensitive_response_fields"]:
                key = op["response"]["schema"].lstrip("[]")
                out.setdefault(key, set()).update(op["sensitive_response_fields"])
    return out


def schema_closure() -> list[str]:
    """Every schema reachable from an operation, transitively, sorted."""
    seeds: set[str] = set()
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            if op["request_schema"]:
                seeds.add(op["request_schema"].lstrip("[]"))
            if op["response"]["schema"]:
                seeds.add(op["response"]["schema"].lstrip("[]"))

    def refs_in(node: Any, found: set[str]) -> None:
        """Collect every ``$ref`` target name appearing anywhere under ``node``."""
        if isinstance(node, list):
            for item in node:
                refs_in(item, found)
        elif isinstance(node, dict):
            if "$ref" in node:
                found.add(node["$ref"].split("/")[-1])
            for value in node.values():
                refs_in(value, found)

    seen: set[str] = set()
    frontier = list(seeds)
    while frontier:
        name = frontier.pop()
        if name in seen or name not in SCHEMAS:
            continue
        seen.add(name)
        found: set[str] = set()
        refs_in(SCHEMAS[name], found)
        frontier.extend(f for f in found if f not in seen)
    return sorted(seen)


def _classify() -> tuple[set[str], set[str]]:
    """Split the spec's schemas into (enums, discriminated unions), by RENDERED name.

    Computed once, up front. A type's NAME never tells you its KIND, and an emitter that
    re-guesses from a name is how a sibling port shipped `Enum::fromArray()` on a backed
    enum.
    """
    enums: set[str] = set()
    unions: set[str] = set()
    for name, schema in SCHEMAS.items():
        if not isinstance(schema, dict):
            continue
        if isinstance(schema.get("enum"), list):
            enums.add(pascal(name))
        elif discriminated(schema):
            unions.add(pascal(name))
    return enums, unions


ENUMS, UNIONS = _classify()


# ---------------------------------------------------------------------------
# C++ naming and types
# ---------------------------------------------------------------------------

MODELS_HPP = "include/axiam/management_models.hpp"
API_HPP = "include/axiam/management.hpp"
MODELS_CPP = "src/management_models.cpp"
OPS_CPP = "src/management_ops.cpp"
TEST_CPP = "tests/test_management_generated.cpp"

BANNER = """// Generated by scripts/gen_management.py from management-registry.json and openapi.json.
// DO NOT EDIT -- your changes will be overwritten. Regenerate with
// `python3 scripts/gen_management.py`; CI verifies the committed output is current.
"""

CPP_KEYWORDS = {
    "alignas", "alignof", "and", "asm", "auto", "bool", "break", "case", "catch",
    "char", "class", "compl", "concept", "const", "consteval", "constexpr", "continue",
    "decltype", "default", "delete", "do", "double", "else", "enum", "explicit",
    "export", "extern", "false", "float", "for", "friend", "goto", "if", "inline",
    "int", "long", "mutable", "namespace", "new", "noexcept", "not", "nullptr",
    "operator", "or", "private", "protected", "public", "register", "requires",
    "return", "short", "signed", "sizeof", "static", "struct", "switch", "template",
    "this", "throw", "true", "try", "typedef", "typeid", "typename", "union",
    "unsigned", "using", "virtual", "void", "volatile", "while", "xor",
}


def member(name: str) -> str:
    """A C++ member name: snake_case per §1, keywords suffixed."""
    ident = snake(pascal(name))
    return f"{ident}_" if ident in CPP_KEYWORDS else ident


def method(name: str) -> str:
    """A C++ method name: snake_case per §27.3's C++ row."""
    ident = snake(pascal(name))
    return f"{ident}_" if ident in CPP_KEYWORDS else ident


def handle_type(namespace: str) -> str:
    """The handle class for a namespace (``service_accounts`` -> ``ServiceAccountsApi``)."""
    return f"{pascal(namespace)}Api"


def doc(text: str, indent: str = "", width: int = 96) -> list[str]:
    """A ``///`` Doxygen block -- this repo publishes an API reference from them."""
    paragraphs = [p for p in str(text).split("\n\n") if p.strip()]
    out: list[str] = []
    first = True
    for para in paragraphs or [""]:
        if not first:
            out.append(f"{indent}///")
        for line in wrap(escape(para), width - len(indent) - 4):
            out.append(f"{indent}/// {line}".rstrip())
        first = False
    return out


def comment(text: str, indent: str = "", width: int = 96) -> list[str]:
    """A ``//`` comment block, for rationale that is not API documentation."""
    return [f"{indent}// {line}".rstrip()
            for line in wrap(escape(text), width - len(indent) - 3)]


# Type names the HAND-WRITTEN core already owns in axiam::management. A model that
# rendered to one of these would silently redefine it -- which is exactly what `Scope`
# did on the first run, since the spec has a schema by that name (a sub-resource
# permission scope) and the per-call override struct had the same one. The generated
# model keeps the spec's name -- renaming it would make C++ the one SDK whose type does
# not match the contract -- and the hand-written type carries a qualifier. This list is
# what makes the NEXT such collision a build failure here rather than a redefinition
# error 3000 lines into a generated header.
RESERVED_TYPES = {"CallScope", "PageRequest", "Page", "Transport", "ManagementApi",
                  "NotFoundError", "ConflictError", "ValidationError", "ManifestApi"}


def model_type(name: str) -> str:
    """The C++ type for a model. Models live in ``axiam::management``."""
    rendered = pascal(name)
    if rendered in RESERVED_TYPES:
        raise SystemExit(
            f"schema {name!r} renders to {rendered!r}, which the hand-written core in "
            "include/axiam/management.hpp already defines. Rename the hand-written type "
            "and add the new name to RESERVED_TYPES -- do NOT rename the model, or C++ "
            "becomes the one SDK whose type does not match the contract."
        )
    return rendered


def enum_value(value: str) -> str:
    """A C++ enum-class enumerator (``pending_review`` -> ``PendingReview``)."""
    rendered = pascal(value)
    if not rendered or not rendered[0].isalpha():
        rendered = f"V{rendered}"
    return f"{rendered}_" if rendered.lower() in CPP_KEYWORDS else rendered


def cpp_field(schema: Any, secret: bool = False) -> dict[str, str]:
    """Map a schema to ``(type, kind)`` for one struct member."""
    if secret:
        return {"decl": "Sensitive<std::string>", "kind": "sensitive", "ref": ""}
    if not isinstance(schema, dict):
        return {"decl": "std::string", "kind": "json_text", "ref": ""}

    if "$ref" in schema:
        name = pascal(schema["$ref"].split("/")[-1])
        return {"decl": name, "kind": "enum" if name in ENUMS else "model", "ref": name}

    inner = nullable_ref(schema)
    if inner:
        name = pascal(inner)
        return {"decl": name, "kind": "enum" if name in ENUMS else "model", "ref": name}

    if isinstance(schema.get("allOf"), list) and len(schema["allOf"]) == 1:
        return cpp_field(schema["allOf"][0])

    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)

    if kind == "array":
        item = cpp_field(schema.get("items") or {})
        if item["kind"] in {"string", "model", "enum"}:
            return {"decl": f"std::vector<{item['decl']}>", "kind": "vector",
                    "ref": item["ref"] or "std::string"}
        # Anything else keeps its JSON shape rather than getting a bespoke C++ type.
        return {"decl": "std::string", "kind": "json_text", "ref": ""}
    if kind == "integer":
        return {"decl": "std::int64_t", "kind": "int", "ref": ""}
    if kind == "number":
        return {"decl": "double", "kind": "double", "ref": ""}
    if kind == "boolean":
        return {"decl": "bool", "kind": "bool", "ref": ""}
    if kind == "string":
        return {"decl": "std::string", "kind": "string", "ref": ""}

    return {"decl": "std::string", "kind": "json_text", "ref": ""}


def fields_of(schema_name: str, secrets: set[str]) -> tuple[list[dict[str, Any]], str | None]:
    """Every member of ``schema_name``, in the spec's own order.

    A discriminated union gets two synthetic members: the discriminator, and the whole
    object as raw JSON. C++ could model a sum type with ``std::variant``, but the arms
    here are open-ended server shapes -- a variant would have to be regenerated and would
    break every switch the moment the server grew an arm, where the tag plus payload
    simply carries the new one through.
    """
    schema = SCHEMAS.get(schema_name) or {}
    union = discriminated(schema)
    if union:
        tag, _arms = union
        return ([
            {"wire": tag, "name": member(tag), "decl": "std::string", "kind": "string",
             "ref": "", "required": True, "schema": {"type": "string"}, "secret": False,
             "description": f"The `{tag}` discriminator naming which variant this is."},
            {"wire": "", "name": "raw", "decl": "std::string", "kind": "union_raw",
             "ref": "", "required": True, "schema": {}, "secret": False,
             "description": "The whole object as the server sent it, to read the "
                            f"variant's own fields from once `{tag}` says which it is."},
        ], schema.get("description"))

    props, required, description = flatten(schema_name)
    out: list[dict[str, Any]] = []
    for wire, sub in props.items():
        info = cpp_field(sub, secret=wire in secrets)
        out.append({
            "wire": wire, "name": member(wire), "decl": info["decl"], "kind": info["kind"],
            "ref": info["ref"], "required": wire in required, "schema": sub,
            "secret": wire in secrets,
            "description": sub.get("description") if isinstance(sub, dict) else None,
        })
    return out, description


def declared(f: dict[str, Any]) -> str:
    """How one member is declared: optional members wear ``std::optional``.

    ``std::optional`` rather than C's ``has_`` flag, and rather than a sentinel: it says
    "absent" in the type, so §27.4 rule 5's "an unset field is OMITTED, not null" is
    something the serializer can act on without a convention to remember.
    """
    return f["decl"] if f["required"] else f"std::optional<{f['decl']}>"


def field_doc(f: dict[str, Any]) -> str:
    """The one-line description for a member."""
    if f["description"]:
        return escape(f["description"])
    if f["secret"]:
        return f"The server's `{f['wire']}` field -- a ONE-TIME secret (§27.5)."
    return f"The server's `{f['wire']}` field."


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def modelled() -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Every schema that becomes a struct, as ``(spec name, C++ name, fields)``."""
    secrets = sensitive_map()
    out = []
    for name in schema_closure():
        rendered = pascal(name)
        if rendered in ENUMS:
            continue
        fields, _ = fields_of(name, secrets.get(name, set()))
        if fields:
            out.append((name, rendered, fields))
    return out



def model_deps(fields: list[dict[str, Any]]) -> set[str]:
    """Model types this struct embeds BY VALUE, and therefore needs complete."""
    out: set[str] = set()
    for f in fields:
        if f["kind"] == "model":
            out.add(f["ref"])
        elif f["kind"] == "vector" and f["ref"] and f["ref"] != "std::string":
            out.add(f["ref"])
    return out


def modelled_ordered() -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Every struct, ordered so a type is defined before anything that embeds it.

    A forward declaration is not enough here: `std::optional<T>` and `std::vector<T>`
    both require a COMPLETE T at the point of instantiation, so a struct holding
    `std::optional<TokenExchangeTrustRequest>` must appear after that struct's
    definition, not merely after its forward declaration.

    Emitted in dependency order rather than solved with indirection, because a
    `unique_ptr` member would change the public API -- every caller would write `*x->y`
    for a field the other ten SDKs expose as a plain value.
    """
    items = modelled()
    by_name = {rendered: (name, rendered, fields) for name, rendered, fields in items}

    out: list[tuple[str, str, list[dict[str, Any]]]] = []
    state: dict[str, str] = {}

    def visit(rendered: str) -> None:
        """Depth-first, deps before dependents."""
        if state.get(rendered) == "done":
            return
        if state.get(rendered) == "open":
            # Two schemas embedding each other by value is not representable in C++ at
            # all -- the struct would have infinite size. The spec has no such pair; if
            # one ever appears, the generator must say so rather than emit code that
            # cannot compile.
            raise SystemExit(
                f"schema cycle through {rendered!r}: two models embed each other by "
                "value, which C++ cannot represent. One side needs indirection."
            )
        entry = by_name.get(rendered)
        if entry is None:
            return
        state[rendered] = "open"
        for dep in sorted(model_deps(entry[2])):
            visit(dep)
        state[rendered] = "done"
        out.append(entry)

    for _name, rendered, _fields in items:
        visit(rendered)
    return out


def enum_values(name: str) -> list[str]:
    """The wire values of an enum schema, in spec order."""
    return [str(v) for v in ((SCHEMAS.get(name) or {}).get("enum") or [])]


def emit_models_header() -> str:
    """The model structs, enums and page/list aliases."""
    secrets = sensitive_map()
    out = [BANNER, ""]
    out.append("#ifndef AXIAM_MANAGEMENT_MODELS_HPP")
    out.append("#define AXIAM_MANAGEMENT_MODELS_HPP")
    out.append("")
    out.append("#include <cstdint>")
    out.append("#include <optional>")
    out.append("#include <string>")
    out.append("#include <vector>")
    out.append("")
    out.append('#include "axiam/sensitive.hpp"')
    out.append("")
    out.extend(comment(
        "This header deliberately does NOT include <nlohmann/json.hpp>. The vendored "
        "single header is a PRIVATE implementation detail -- CMake adds third_party/ to "
        "the PRIVATE include path and no other public header names it -- so exposing it "
        "here would put a third-party type in the installed API and force nlohmann onto "
        "every consumer's include path.\n\n"
        "A free-form JSON member (`metadata`, `attribute_map`) is therefore raw JSON "
        "TEXT, which the caller hands to whatever parser they already use. The "
        "to_json/from_json hooks live in src/management_json.hpp, which is not "
        "installed."))
    out.append("")
    out.append("namespace axiam::management {")
    out.append("")

    # ---- enums ----
    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS:
            continue
        values = enum_values(name)
        if not values:
            continue
        out.extend(doc((SCHEMAS.get(name) or {}).get("description")
                       or f"The `{rendered}` enumeration from the server's OpenAPI document."))
        out.append(f"enum class {rendered} {{")
        for value in values:
            out.append(f"    {enum_value(value)},  ///< Wire value `{value}`.")
        out.append("};")
        out.append("")
        out.extend(doc(
            f"The wire spelling of a {rendered}."))
        out.append(f"std::string to_wire({rendered} value);")
        out.append("")
        out.extend(doc(
            f"Parse a wire value into a {rendered}.\n\n"
            "Throws rather than mapping an unrecognised value to a default enumerator: on "
            "this surface these values gate access, and silently reading a state this SDK "
            "does not know as whichever enumerator happens to be first turns a newer "
            "server into a wrong answer."))
        out.append(f"{rendered} {snake(rendered)}_from_wire(const std::string& value);")
        out.append("")

    # ---- forward declarations ----
    structs = [rendered for _, rendered, _ in modelled()]
    out.extend(comment(
        "Forward declarations. The spec's types reference each other freely and in both "
        "directions, so every struct is named before any is defined."))
    for rendered in structs:
        out.append(f"struct {rendered};")
    out.append("")

    # ---- structs ----
    for name, rendered, fields in modelled_ordered():
        _, description = fields_of(name, secrets.get(name, set()))
        summary = escape(description) if description else \
            f"The `{rendered}` schema from the server's OpenAPI document."
        sparse = all(not f["required"] for f in fields)
        if sparse:
            summary += (
                "\n\nEvery member is optional, so this is a SPARSE body: an engaged "
                "`std::optional` is sent and a disengaged one is OMITTED from the request "
                "entirely, rather than sent as null (§27.4 rule 5). On a sparse update "
                "those say opposite things, and only omission means \"leave it alone\".")
        out.extend(doc(summary))
        out.append(f"struct {rendered} {{")
        for f in fields:
            out.extend(doc(field_doc(f) + ("" if f["required"] else " Optional."), "    "))
            default = "" if f["required"] else " = std::nullopt"
            out.append(f"    {declared(f)} {f['name']}{default};")
        out.append("};")
        out.append("")

    out.append("}  // namespace axiam::management")
    out.append("")
    out.append("#endif  // AXIAM_MANAGEMENT_MODELS_HPP")
    return "\n".join(out) + "\n"


def emit_to_json_member(f: dict[str, Any]) -> list[str]:
    """Serialize one member. A disengaged optional is OMITTED, never emitted as null."""
    w, n, kind = f["wire"], f["name"], f["kind"]
    ref = f"value.{n}" if f["required"] else f"*value.{n}"

    if kind == "union_raw":
        return []

    if kind == "json_text":
        parse = f"nlohmann::json::parse(value.{n}, nullptr, false)"
        if f["required"]:
            return [f'    {{ auto parsed = {parse}; if (!parsed.is_discarded()) j["{w}"] = parsed; }}']
        return [
            f"    if (value.{n}) {{",
            f"        auto parsed = nlohmann::json::parse(*value.{n}, nullptr, false);",
            f'        if (!parsed.is_discarded()) j["{w}"] = parsed;',
            "    }",
        ]

    if kind == "sensitive":
        # §27.5: this is the one place a secret is revealed, on the way to the wire.
        expr = f"detail::reveal({ref})"
    elif kind == "enum":
        expr = f"to_wire({ref})"
    else:
        expr = ref

    if f["required"]:
        return [f'    j["{w}"] = {expr};']
    return [
        f"    if (value.{n}) {{",
        f'        j["{w}"] = {expr};',
        "    }",
    ]


def emit_from_json_member(f: dict[str, Any]) -> list[str]:
    """Deserialize one member, tolerating both an absent key and an explicit null."""
    w, n, kind = f["wire"], f["name"], f["kind"]

    if kind == "union_raw":
        return ["    value.raw = j.dump();"]

    if kind == "json_text":
        if f["required"]:
            return [f'    value.{n} = j.at("{w}").dump();']
        return [
            f'    if (auto it = j.find("{w}"); it != j.end() && !it->is_null()) {{',
            f"        value.{n} = it->dump();",
            "    }",
        ]

    if kind == "sensitive":
        read = f'Sensitive<std::string>(j.at("{w}").get<std::string>())'
        opt_read = f'Sensitive<std::string>(it->get<std::string>())'
    elif kind == "enum":
        read = f'{snake(f["ref"])}_from_wire(j.at("{w}").get<std::string>())'
        opt_read = f'{snake(f["ref"])}_from_wire(it->get<std::string>())'
    else:
        read = f'j.at("{w}").get<{f["decl"]}>()'
        opt_read = f'it->get<{f["decl"]}>()'

    if f["required"]:
        return [f"    value.{n} = {read};"]
    return [
        f'    if (auto it = j.find("{w}"); it != j.end() && !it->is_null()) {{',
        f"        value.{n} = {opt_read};",
        "    }",
    ]


def emit_models_source() -> str:
    """to_json / from_json for every model, plus the enum conversions."""
    secrets = sensitive_map()
    out = [BANNER, ""]
    out.append("#include <stdexcept>")
    out.append("")
    out.append('#include "management_json.hpp"')
    out.append("")
    out.append("namespace axiam::management {")
    out.append("")

    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS:
            continue
        values = enum_values(name)
        if not values:
            continue
        out.append(f"std::string to_wire({rendered} value) {{")
        out.append("    switch (value) {")
        for v in values:
            out.append(f'        case {rendered}::{enum_value(v)}: return "{v}";')
        out.append("    }")
        out.extend(comment(
            "Unreachable for a value produced by this SDK; present because a switch over "
            "an enum class with an out-of-range value is otherwise undefined.", "    "))
        out.append(f'    return "{values[0]}";')
        out.append("}")
        out.append("")
        out.append(f"{rendered} {snake(rendered)}_from_wire(const std::string& value) {{")
        for v in values:
            out.append(f'    if (value == "{v}") return {rendered}::{enum_value(v)};')
        out.extend(comment(
            "No default enumerator, on purpose: an unrecognised value is reported rather "
            "than mapped to whichever one happens to be first.", "    "))
        out.append(f'    throw std::invalid_argument("unknown {rendered} value \\"" + value + '
                   '"\\" -- the server may be newer than this SDK");')
        out.append("}")
        out.append("")
        out.append(f"void to_json(nlohmann::json& j, const {rendered}& value) {{ j = to_wire(value); }}")
        out.append(f"void from_json(const nlohmann::json& j, {rendered}& value) {{")
        out.append(f"    value = {snake(rendered)}_from_wire(j.get<std::string>());")
        out.append("}")
        out.append("")

    for _name, rendered, fields in modelled_ordered():
        out.append(f"void to_json(nlohmann::json& j, const {rendered}& value) {{")
        if any(f["kind"] == "union_raw" for f in fields):
            out.extend(comment(
                "A union is forwarded EXACTLY as received. Re-encoding from the two "
                "members this SDK models would drop every field belonging to the variant "
                "it does not model -- and the server round-trips those.", "    "))
            out.append("    j = nlohmann::json::parse(value.raw, nullptr, false);")
            out.append("    if (j.is_discarded()) j = nlohmann::json::object();")
            out.append("}")
            out.append("")
            out.append(f"void from_json(const nlohmann::json& j, {rendered}& value) {{")
            for f in fields:
                out.extend(emit_from_json_member(f))
            out.append("}")
            out.append("")
            continue

        out.append("    j = nlohmann::json::object();")
        for f in fields:
            out.extend(emit_to_json_member(f))
        out.append("}")
        out.append("")
        out.append(f"void from_json(const nlohmann::json& j, {rendered}& value) {{")
        for f in fields:
            out.extend(emit_from_json_member(f))
        out.append("}")
        out.append("")

    out.append("}  // namespace axiam::management")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Namespace handles (§27.2 / §27.3's C++ row)
# ---------------------------------------------------------------------------


def path_params(op: dict[str, Any]) -> list[str]:
    return re.findall(r"\{([^}]+)\}", op["path"])


def implicit_of(namespace: str, op: dict[str, Any]) -> set[str]:
    """Which path parameters the SDK fills in from the client (§27.4 rule 3)."""
    names = set(path_params(op))
    out = {"org_id"} & names
    if "tenant_id" in names and namespace in IMPLICIT_TENANT_NAMESPACES:
        out.add("tenant_id")
    return out


def paginated_models() -> list[str]:
    out: set[str] = set()
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            if op["response"]["kind"] == "page" and op["response"]["schema"]:
                out.add(pascal(op["response"]["schema"].lstrip("[]")))
    return sorted(out)


def op_params(namespace: str, op: dict[str, Any]) -> list[dict[str, str]]:
    """The C++ parameter list for one operation, required before defaulted."""
    implicit = implicit_of(namespace, op)
    params: list[dict[str, str]] = []

    for name in path_params(op):
        if name in implicit:
            continue
        params.append({"name": member(name), "decl": "const std::string&", "kind": "path",
                       "wire": name, "required": "1",
                       "text": f"The `{{{name}}}` path parameter."})

    for q in op["query_params"]:
        if op["paginated"] and q["name"] in {"offset", "limit"}:
            continue
        if q["required"]:
            params.append({"name": member(q["name"]), "decl": "const std::string&",
                           "kind": "query", "wire": q["name"], "required": "1",
                           "text": f"The required `{q['name']}` query parameter."})

    if op["request_body"] != "none" and op["request_schema"]:
        model = model_type(op["request_schema"].lstrip("[]"))
        params.append({"name": "body", "decl": f"const {model}&", "kind": "body",
                       "wire": "", "required": "1", "text": "The request body."})

    if op["paginated"]:
        params.append({"name": "page", "decl": "const PageRequest&", "kind": "page",
                       "wire": "", "required": "",
                       "text": "Which page to fetch; defaults to the first."})

    for q in op["query_params"]:
        if op["paginated"] and q["name"] in {"offset", "limit"}:
            continue
        if not q["required"]:
            params.append({"name": member(q["name"]),
                           "decl": "const std::optional<std::string>&", "kind": "query",
                           "wire": q["name"], "required": "",
                           "text": f"The optional `{q['name']}` query parameter."})

    return params


def response_cpp(op: dict[str, Any]) -> str:
    """The operation's return type."""
    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    if kind == "none" or not schema:
        return "void"
    model = model_type(schema.lstrip("[]"))
    if kind == "page":
        return f"Page<{model}>"
    if kind == "array":
        return f"std::vector<{model}>"
    return model


def op_doc(namespace: str, opname: str, op: dict[str, Any]) -> str:
    """The Doxygen summary for one operation."""
    entry = (SPEC.get("paths") or {}).get(op["path"]) or {}
    node = entry.get(op["method"].lower()) or {}
    described = node.get("summary") or node.get("description")

    lead = f"`{op['method']} {op['path']}`."
    if described:
        lead = f"{escape(described)}\n\n`{op['method']} {op['path']}`."

    kind = op["response"]["kind"]
    if kind == "page":
        lead += ("\n\nReturns ONE page. `Page::total` is the server's count across all "
                 "pages and is not `items.size()` -- see §27.4 rule 4.")
    elif kind == "array":
        lead += ("\n\nReturns the server's complete list. This endpoint is NOT paginated, "
                 "so the result is a plain vector and never a Page (§27.4 rule 4).")
    elif kind == "none":
        lead += "\n\nReturns nothing; the server answers with an empty body."

    if op["method"] == "DELETE":
        lead += ("\n\nNOT idempotent (§27.4 rule 6): deleting something already deleted "
                 "throws NotFoundError rather than succeeding quietly.")
    if op["sensitive_response_fields"]:
        fields = ", ".join(f"`{f}`" for f in op["sensitive_response_fields"])
        lead += (f"\n\nThe response carries a ONE-TIME secret ({fields}): the server will "
                 "not return it again, so a caller that does not persist it here cannot "
                 "recover it (§27.5).")
    return lead


def op_decl(namespace: str, opname: str, op: dict[str, Any], defaults: bool) -> str:
    """One operation's declaration; ``defaults`` controls default arguments."""
    params = op_params(namespace, op)
    args = []
    for p in params:
        default = ""
        if defaults and not p["required"]:
            default = " = {}" if p["kind"] == "page" else " = std::nullopt"
        args.append(f"{p['decl']} {p['name']}{default}")
    return f"{response_cpp(op)} {method(opname)}({', '.join(args)})"


def emit_api_header() -> str:
    """The 24 namespace handles, the Page/PageRequest types, and the §27.4 errors."""
    out = [BANNER, ""]
    out.append("#ifndef AXIAM_MANAGEMENT_HPP")
    out.append("#define AXIAM_MANAGEMENT_HPP")
    out.append("")
    out.append("#include <cstdint>")
    out.append("#include <memory>")
    out.append("#include <optional>")
    out.append("#include <string>")
    out.append("#include <vector>")
    out.append("")
    out.append('#include "axiam/errors.hpp"')
    out.append('#include "axiam/management_models.hpp"')
    out.append("")
    out.append("namespace axiam {")
    out.append("class Client;")
    out.append("}")
    out.append("")
    out.append("namespace axiam::management {")
    out.append("")
    out.extend(doc(
        "One page's worth of `?offset=`/`?limit=` (§27.4 rule 4).\n\n"
        "Default-constructed means the first page at the server's default size, which is "
        "what a caller who does not care about paging gets by writing nothing."))
    out.append("struct PageRequest {")
    out.append("    std::int64_t offset = 0;   ///< How many items to skip; clamped at 0.")
    out.append("    std::int64_t limit = 50;   ///< How many to ask for; clamped to at least 1.")
    out.append("")
    out.extend(doc(
        "The page after this one -- same size, advanced by exactly `limit`.\n\n"
        "By the requested limit, not by how many items came back: §27.4 rule 4 stops "
        "auto-paging on an EMPTY page, not a short one, and advancing by a short count "
        "would re-request rows the caller has already seen.", "    "))
    out.append("    PageRequest next() const;")
    out.append("};")
    out.append("")
    out.extend(doc(
        "One page of a paginated response (§27.4 rule 4).\n\n"
        "`total` is the SERVER's count across every page. It is NOT `items.size()`, and "
        "deriving one from the other is how a management tool silently processes the "
        "first fifty of four hundred rows -- so they are separate members and neither is "
        "computed from the other.\n\n"
        "A bare JSON array response is NOT a page and is never modelled as one; those "
        "operations return a plain `std::vector`."))
    out.append("template <typename T>")
    out.append("struct Page {")
    out.append("    std::vector<T> items;     ///< The items on THIS page.")
    out.append("    std::int64_t total = 0;   ///< The server's total across all pages.")
    out.append("    PageRequest request;      ///< The request that produced this page.")
    out.append("")
    out.append("    /// How many items are on THIS page. Deliberately not `total`.")
    out.append("    std::size_t size() const noexcept { return items.size(); }")
    out.append("")
    out.append("    /// True when this page carried nothing -- §27.4 rule 4's stop condition.")
    out.append("    bool empty() const noexcept { return items.empty(); }")
    out.append("")
    out.append("    auto begin() const noexcept { return items.begin(); }")
    out.append("    auto end() const noexcept { return items.end(); }")
    out.append("")
    out.append("    /// The request that would fetch the page after this one.")
    out.append("    PageRequest next_request() const { return request.next(); }")
    out.append("};")
    out.append("")

    out.extend(doc(
        "`404 Not Found` on the management surface -- §27.4 rule 7.\n\n"
        "Derives from AuthzError, which is not the obvious parent and is the point. AXIAM "
        "is multi-tenant, and the server answers `404` for an object belonging to another "
        "tenant PRECISELY SO a probing caller cannot tell \"does not exist\" from "
        "\"exists, not yours\". Classifying it as an authorization outcome keeps the SDK "
        "from re-drawing a line the server deliberately refused to draw.\n\n"
        "A `catch (const AuthzError&)` written before §27 existed still catches it, which "
        "is exactly the property the rule asks for -- and AuthzChallengeError already set "
        "that precedent here."))
    out.append("class NotFoundError : public AuthzError {")
    out.append("public:")
    out.append("    explicit NotFoundError(const std::string& message) : AuthzError(message) {}")
    out.append("};")
    out.append("")
    out.extend(doc(
        "`409 Conflict` on the management surface -- §27.4 rule 7.\n\n"
        "Derives from AuthzError because §2 already maps `409` there as a resource-level "
        "refusal; rule 7 KEEPS that mapping rather than moving it."))
    out.append("class ConflictError : public AuthzError {")
    out.append("public:")
    out.append("    explicit ConflictError(const std::string& message) : AuthzError(message) {}")
    out.append("};")
    out.append("")
    out.extend(doc(
        "`400`/`422` on the management surface -- §27.4 rule 7.\n\n"
        "Derives from NetworkError, inherited from §2's own `400` row. That placement has "
        "one consequence worth naming: §16 retries NetworkError, so without care a body "
        "the server has already rejected would be sent three times. §27.4 rule 8 (only "
        "GET is retried) and an explicit exclusion for this type are what stop it."))
    out.append("class ValidationError : public NetworkError {")
    out.append("public:")
    out.append("    explicit ValidationError(const std::string& message) : NetworkError(message) {}")
    out.append("};")
    out.append("")

    out.extend(doc(
        "Per-call override of the `{org_id}`/`{tenant_id}` a route substitutes (§27.4 "
        "rule 3).\n\n"
        "Applied with a handle's `in_org()` / `for_tenant()`, which return a NEW handle "
        "rather than mutating the one you called them on. An administrator holding a "
        "handle to their own tenant should not find it repointed at someone else's "
        "because an unrelated code path re-scoped a shared object -- and on a management "
        "surface that failure mode WRITES to the wrong tenant."))
    out.append("struct CallScope {")
    out.append("    std::optional<std::string> org_id;     ///< Overrides `{org_id}`.")
    out.append("    std::optional<std::string> tenant_id;  ///< Overrides `{tenant_id}`.")
    out.append("};")
    out.append("")
    out.append("class Transport;    // defined in src/management_transport.hpp")
    out.append("class ManifestApi;  // defined in axiam/management_manifest.hpp")
    out.append("")

    # ---- handles ----
    for namespace, nsdef in REGISTRY["namespaces"].items():
        cls = handle_type(namespace)
        out.extend(doc(
            escape(nsdef["doc"]) +
            f"\n\nThe `{namespace}` namespace handle (§27.2), reached as "
            f"`client.management().{method(namespace)}()`. §27.3's C++ row is "
            "`client.service_accounts().rotate_secret(id)` -- a method returning a handle, "
            "snake_case -- and that is what this is.\n\n"
            "Every method goes through the one shared transport, so §3 CSRF, the §4 cookie "
            "jar, the §5 tenant header, §6 TLS, §16 retry and §19 telemetry apply without "
            "this class doing anything to opt in (§27.8)."))
        out.append(f"class {cls} {{")
        out.append("public:")
        out.append(f"    {cls}(std::shared_ptr<Transport> transport, CallScope scope);")
        out.append("")
        out.extend(doc(
            "A COPY of this handle scoped to `org_id` (§27.4 rule 3). Returns a new handle; "
            "the one you called it on is untouched.", "    "))
        out.append(f"    {cls} in_org(std::string org_id) const;")
        out.append("")
        out.extend(doc(
            "A COPY of this handle scoped to `tenant_id` (§27.4 rule 3). See in_org().",
            "    "))
        out.append(f"    {cls} for_tenant(std::string tenant_id) const;")
        out.append("")
        for opname, op in nsdef["operations"].items():
            tags = [f"@param {p['name']} {p['text']}" for p in op_params(namespace, op)]
            block = doc(op_doc(namespace, opname, op), "    ")
            if tags:
                block.append("    ///")
                block.extend(f"    /// {t}" for t in tags)
            out.extend(block)
            out.append(f"    {op_decl(namespace, opname, op, defaults=True)};")
            out.append("")
        out.append("private:")
        out.append("    std::shared_ptr<Transport> transport_;")
        out.append("    CallScope scope_;")
        out.append("};")
        out.append("")

    # ---- root ----
    out.extend(doc(
        "The CONTRACT.md §27 management surface: 146 operations across 24 namespaces.\n\n"
        "Reached as `client.management()`. Each accessor hands back a namespace handle "
        "(§27.2) that can be re-scoped per call with `in_org()` / `for_tenant()`.\n\n"
        "Handles are constructed on demand rather than cached. §27.4 rule 10 forbids "
        "caching RESPONSES, not handles -- but a handle is a shared pointer and a scope, "
        "and building one per call keeps `in_org()` from having anything shared to mutate."))
    out.append("class ManagementApi {")
    out.append("public:")
    out.append("    explicit ManagementApi(std::shared_ptr<Transport> transport, CallScope scope);")
    out.append("")
    for namespace, nsdef in REGISTRY["namespaces"].items():
        out.extend(doc(escape(nsdef["doc"]), "    "))
        out.append(f"    {handle_type(namespace)} {method(namespace)}() const;")
        out.append("")
    out.extend(doc(
        "The §27.6 declarative layer: plan and apply a manifest.\n\n"
        "`plan()` writes nothing; `apply()` performs the plan, stops at the first failure "
        "and does not roll back (§27.7).", "    "))
    out.append("    ManifestApi manifest() const;")
    out.append("")
    out.append("private:")
    out.append("    std::shared_ptr<Transport> transport_;")
    out.append("    CallScope scope_;")
    out.append("};")
    out.append("")
    out.append("}  // namespace axiam::management")
    out.append("")
    out.append("#endif  // AXIAM_MANAGEMENT_HPP")
    return "\n".join(out) + "\n"


JSON_HPP = "src/management_json.hpp"


def emit_json_header() -> str:
    """The nlohmann ADL hooks, in an INTERNAL header.

    Separate from the public models header because the vendored nlohmann single header is
    a private implementation detail of this library -- putting `nlohmann::json` in an
    installed header would make every consumer of the SDK a consumer of our JSON library
    too, pinned to our version of it.
    """
    out = [BANNER, ""]
    out.append("#ifndef AXIAM_MANAGEMENT_JSON_HPP")
    out.append("#define AXIAM_MANAGEMENT_JSON_HPP")
    out.append("")
    out.append("#include <nlohmann/json.hpp>")
    out.append("")
    out.append('#include "axiam/management_models.hpp"')
    out.append("")
    out.append("namespace axiam::management {")
    out.append("")
    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS or not enum_values(name):
            continue
        out.append(f"void to_json(nlohmann::json& j, const {rendered}& value);")
        out.append(f"void from_json(const nlohmann::json& j, {rendered}& value);")
    out.append("")
    out.extend(comment(
        "to_json OMITS a disengaged optional rather than emitting null (§27.4 rule 5). On "
        "a sparse update those say opposite things -- \"erase this\" versus \"leave it "
        "alone\" -- and only omission means the second."))
    for _name, rendered, _fields in modelled_ordered():
        out.append(f"void to_json(nlohmann::json& j, const {rendered}& value);")
        out.append(f"void from_json(const nlohmann::json& j, {rendered}& value);")
    out.append("")
    out.append("}  // namespace axiam::management")
    out.append("")
    out.append("#endif  // AXIAM_MANAGEMENT_JSON_HPP")
    return "\n".join(out) + "\n"



# ---------------------------------------------------------------------------
# Operation implementations
# ---------------------------------------------------------------------------


def emit_op_body(namespace: str, opname: str, op: dict[str, Any]) -> list[str]:
    """One operation implementation on its handle."""
    params = op_params(namespace, op)
    implicit = implicit_of(namespace, op)
    canonical = f"{namespace}.{opname}"
    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    cls = handle_type(namespace)

    out = [f"{response_cpp(op)} {cls}::{op_decl(namespace, opname, op, defaults=False).split(' ', 1)[1]} {{"]

    # path values
    entries = []
    for name in path_params(op):
        if name == "org_id" and name in implicit:
            entries.append('{"org_id", transport_->org_id(scope_)}')
        elif name == "tenant_id" and name in implicit:
            entries.append('{"tenant_id", transport_->tenant_id(scope_)}')
        else:
            entries.append(f'{{"{name}", {member(name)}}}')
    out.append("    const std::vector<PathValue> values{" + ", ".join(entries) + "};")

    # query values
    queries = [p for p in params if p["kind"] == "query"]
    if op["paginated"]:
        out.append("    auto query = Transport::paging(page);")
        for p in queries:
            out.append(f'    query.push_back({{"{p["wire"]}", {p["name"]}}});')
    elif queries:
        out.append("    const std::vector<QueryValue> query{"
                   + ", ".join(f'{{"{p["wire"]}", {p["name"]}}}' for p in queries) + "};")
    else:
        out.append("    const std::vector<QueryValue> query{};")

    body_param = next((p for p in params if p["kind"] == "body"), None)
    body_expr = "nlohmann::json(body)" if body_param else "std::nullopt"
    if body_param:
        out.append("    const std::optional<nlohmann::json> payload = nlohmann::json(body);")
    else:
        out.append("    const std::optional<nlohmann::json> payload = std::nullopt;")

    call = (f'    const auto response = transport_->send("{canonical}", "{op["method"]}", '
            f'"{op["path"]}",\n                                            values, query, payload);')
    if kind == "none" or not schema:
        out.append(call.replace("const auto response = ", "", 1))
        out.append("}")
        return out

    out.append(call)
    out.append("")
    model = model_type(schema.lstrip("[]"))
    if kind == "page":
        out.append(f"    return Transport::to_page<{model}>(response, page, \"{canonical}\");")
    elif kind == "array":
        out.append(f"    return Transport::decode<std::vector<{model}>>(response, \"{canonical}\");")
    else:
        out.append(f"    return Transport::decode<{model}>(response, \"{canonical}\");")
    out.append("}")
    return out


def emit_ops_source() -> str:
    """The 24 handle classes' implementations, plus Client::management()."""
    out = [BANNER, ""]
    out.append('#include "axiam/management.hpp"')
    out.append("")
    out.append('#include "management_json.hpp"')
    out.append('#include "management_transport.hpp"')
    out.append("")
    out.extend(comment(
        "management_json.hpp before management_transport.hpp on purpose: nlohmann finds "
        "from_json/to_json by ADL at the point a template is INSTANTIATED, and "
        "Transport::to_page<T> instantiates get<T>() -- so the hooks must already be "
        "declared when that header is parsed."))
    out.append("")
    out.append("namespace axiam::management {")
    out.append("")

    for namespace, nsdef in REGISTRY["namespaces"].items():
        cls = handle_type(namespace)
        out.append(f"{cls}::{cls}(std::shared_ptr<Transport> transport, CallScope scope)")
        out.append("    : transport_(std::move(transport)), scope_(std::move(scope)) {}")
        out.append("")
        out.extend(comment(
            "A COPY, not a mutation. §27.4 rule 3: an administrator holding a handle to "
            "their own tenant should not find it repointed at someone else's because an "
            "unrelated code path re-scoped a shared object -- and on a management surface "
            "that failure mode writes to the wrong tenant rather than merely reading."))
        out.append(f"{cls} {cls}::in_org(std::string org) const {{")
        out.append("    CallScope next = scope_;")
        out.append("    next.org_id = std::move(org);")
        out.append(f"    return {cls}(transport_, std::move(next));")
        out.append("}")
        out.append("")
        out.append(f"{cls} {cls}::for_tenant(std::string tenant) const {{")
        out.append("    CallScope next = scope_;")
        out.append("    next.tenant_id = std::move(tenant);")
        out.append(f"    return {cls}(transport_, std::move(next));")
        out.append("}")
        out.append("")
        for opname, op in nsdef["operations"].items():
            out.extend(emit_op_body(namespace, opname, op))
            out.append("")

    out.append("ManagementApi::ManagementApi(std::shared_ptr<Transport> transport, CallScope scope)")
    out.append("    : transport_(std::move(transport)), scope_(std::move(scope)) {}")
    out.append("")
    for namespace in REGISTRY["namespaces"]:
        cls = handle_type(namespace)
        out.append(f"{cls} ManagementApi::{method(namespace)}() const {{")
        out.append(f"    return {cls}(transport_, scope_);")
        out.append("}")
        out.append("")

    out.append("}  // namespace axiam::management")
    out.append("")
    out.append("namespace axiam {")
    out.append("")
    out.extend(comment(
        "The one place the §27 surface is attached to a Client. Defined here rather than "
        "in client.cpp so that translation unit keeps knowing nothing about the 146 "
        "generated operations."))
    out.append("management::ManagementApi Client::management() {")
    out.append("    p_->ensure_open();")
    out.append("    management::CallScope scope;")
    out.append("    return management::ManagementApi("
               "std::make_shared<management::Transport>(p_), std::move(scope));")
    out.append("}")
    out.append("")

    out.extend(comment(
        "§27.2/§27.3: the namespace handles also sit DIRECTLY on the client, which is "
        "the form §27.3's C++ row shows -- `client.service_accounts().rotate_secret(id)`. "
        "§27.2 rule 4 makes the single `management()` accessor above the ADDITIONAL one, "
        "and requires that where an SDK offers both they return equivalent handles; "
        "these forward to it, so equivalence is structural rather than a promise two "
        "code paths have to keep."))
    for namespace in REGISTRY["namespaces"]:
        cls = f"management::{handle_type(namespace)}"
        out.append(f"{cls} Client::{method(namespace)}() {{")
        out.append(f"    return management().{method(namespace)}();")
        out.append("}")
        out.append("")

    out.append("}  // namespace axiam")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Generated conformance test
# ---------------------------------------------------------------------------


def example_json(schema: Any, depth: int = 0) -> Any:
    """A plausible wire value for ``schema`` -- what the fake transport returns."""
    if depth > 6 or not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        return example_for(schema["$ref"].split("/")[-1], depth + 1)
    inner = nullable_ref(schema)
    if inner:
        return example_for(inner, depth + 1)
    if isinstance(schema.get("allOf"), list) and len(schema["allOf"]) == 1:
        return example_json(schema["allOf"][0], depth)
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind == "array":
        return [example_json(schema.get("items") or {}, depth + 1)]
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.5
    if kind == "boolean":
        return True
    if kind == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return EXAMPLE_UUID
        if fmt == "date-time":
            return EXAMPLE_TIME
        return "example"
    if kind == "object" or "properties" in schema or "additionalProperties" in schema:
        return {k: example_json(v, depth + 1) for k, v in (schema.get("properties") or {}).items()}
    return {}


def example_for(name: str, depth: int = 0) -> Any:
    """A plausible wire object for the named schema."""
    if depth > 6:
        return None
    schema = SCHEMAS.get(name) or {}
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    union = discriminated(schema)
    if union:
        tag, arms = union
        value, payload = arms[0]
        resolved = resolve_ref(payload) if "$ref" in payload else payload
        out = {tag: value}
        for k, sub in (resolved.get("properties") or {}).items():
            out[k] = example_json(sub, depth + 1)
        return out
    props, _, _ = flatten(name)
    return {k: example_json(v, depth + 1) for k, v in props.items()}


def example_response(op: dict[str, Any]) -> Any:
    """The body the fake transport returns, honouring ``response.kind``.

    Reads ``response.kind`` and never infers plurality from the schema NAME -- the
    registry's ``response.schema`` carries no ``[]`` prefix, so a generator guessing from
    the name types all 13 bare-array reads as single objects.
    """
    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    if kind == "none" or not schema:
        return None
    body = example_for(schema.lstrip("[]"))
    if kind == "page":
        return {"items": [body], "total": 1, "offset": 0, "limit": 50}
    if kind == "array":
        return [body]
    return body


def cpp_raw_string(text: str) -> str:
    """A raw string literal, so a JSON fixture needs no escaping."""
    return 'R"json(' + text + ')json"'


def expected_path(op: dict[str, Any]) -> str:
    return re.sub(r"\{[^}]+\}", EXAMPLE_UUID, op["path"])


def emit_test() -> str:
    """One conformance case per operation: right method, right path, decodes."""
    out = [BANNER, ""]
    out.append("#include <string>")
    out.append("")
    out.append('#include "assert.hpp"')
    out.append('#include "axiam/axiam.hpp"')
    out.append('#include "axiam/management.hpp"')
    out.append('#include "management_test_util.hpp"')
    out.append("")
    out.extend(comment(
        "One case per CONTRACT.md §27 operation -- all 146 of them.\n\n"
        "Each asserts the operation issues the METHOD the registry names against the PATH "
        "the registry names, and that the response decodes into the model without "
        "throwing. The fake transport sits at the BOTTOM of the real client, so a §27.8 "
        "violation (an operation opening its own request path) fails these rather than "
        "passing them.\n\n"
        "Generated by scripts/gen_management.py; CI re-runs it with --check."))
    out.append("")
    out.append("namespace {")
    out.append("")
    out.append("using namespace axiam;")
    out.append("using namespace axiam::management;")
    out.append("")

    count = 0
    for namespace, nsdef in REGISTRY["namespaces"].items():
        for opname, op in nsdef["operations"].items():
            count += 1
            params = op_params(namespace, op)
            body = example_response(op)
            name = f"management {namespace}.{opname} reaches its route"

            out.append(f'AXIAM_TEST("{name}") {{')
            if body is None:
                out.append("    auto fixture = axtest::mgmt::signed_in(204, \"\");")
            else:
                out.append("    auto fixture = axtest::mgmt::signed_in(200,")
                out.append("        " + cpp_raw_string(json.dumps(body)) + ");")

            args = []
            for p in params:
                if p["kind"] == "path":
                    args.append(f'"{EXAMPLE_UUID}"')
                elif p["kind"] == "query" and p["required"]:
                    args.append('"example"')
                elif p["kind"] == "body":
                    bmodel = model_type(op["request_schema"].lstrip("[]"))
                    out.append(f"    {bmodel} body{{}};")
                    args.append("body")
            call = (f"fixture.client.management().{method(namespace)}()."
                    f"{method(opname)}(" + ", ".join(args) + ")")
            if op["response"]["kind"] == "none" or not op["response"]["schema"]:
                out.append(f"    {call};")
            else:
                out.append(f"    const auto result = {call};")
                out.append("    (void) result;")
            out.append("")
            out.append(f'    AXIAM_CHECK(fixture.state->last().method == "{op["method"]}");')
            out.append("    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "
                       f'"{expected_path(op)}");')
            out.append("}")
            out.append("")

    out.extend(comment(
        "§27.9: all 146 registry operations are covered by a case above.\n\n"
        "Counted from the test registry rather than written as a literal on both sides. "
        "`AXIAM_CHECK(146 == 146)` is a tautology, and a case removed by a bad "
        "regeneration would still pass it -- this fails instead."))
    out.append(f'AXIAM_TEST("management surface covers all {count} registry operations") {{')
    out.append("    int reached = 0;")
    out.append("    for (const auto& test : axtest::registry()) {")
    out.append('        if (test.name.rfind("management ", 0) == 0 &&')
    out.append('            test.name.find("reaches its route") != std::string::npos) {')
    out.append("            ++reached;")
    out.append("        }")
    out.append("    }")
    out.append(f"    AXIAM_CHECK(reached == {count});")
    out.append("}")
    out.append("")
    out.append("}  // namespace")
    return "\n".join(out) + "\n"



MODELS_TEST_CPP = "tests/test_management_models_generated.cpp"


def emit_models_test() -> str:
    """Round-trip every model and every enum, and scope every namespace handle.

    The operation suite in ``test_management_generated.cpp`` proves each route is
    reached and that its response DECODES. That leaves three things it cannot see, all
    of which fail silently:

    * a model whose ``to_json`` drops a field ``from_json`` reads -- the operation suite
      only ever decodes, so a write-side omission never surfaces;
    * an enumerator no fixture happens to carry, whose wire spelling is therefore
      whatever the generator wrote and nothing has ever compared against the spec;
    * ``in_org()`` / ``for_tenant()``, which are 48 functions the operation suite never
      calls because it always uses the client's own scope.

    So the assertions here are: encode-after-decode equals the wire object exactly
    (nothing dropped, nothing invented), every enumerator survives both directions and
    an unknown value is REPORTED rather than mapped to the first enumerator, and a
    re-scoped handle is a NEW handle that leaves the original pointing where it was.

    Reaches ``management_json.hpp``, which is internal rather than installed: the ADL
    hooks are an implementation detail of the request path, and a test is the one place
    that detail is worth addressing directly. ``tests/test_refresh_guard.cpp`` does the
    same for the §9 guard, which is why ``src/`` is on the test target's include path.

    Generated by scripts/gen_management.py; CI re-runs it with --check.
    """
    out = [BANNER, ""]
    out.append("#include <stdexcept>")
    out.append("#include <string>")
    out.append("")
    out.append('#include "assert.hpp"')
    out.append('#include "axiam/axiam.hpp"')
    out.append('#include "axiam/management.hpp"')
    out.append("")
    out.extend(comment(
        "Internal, not installed -- see the generator's emit_models_test() docstring."))
    out.append('#include "management_json.hpp"')
    out.append("")
    out.append('#include "management_test_util.hpp"')
    out.append("")
    out.append("namespace {")
    out.append("")
    out.extend(comment(
        "Only the management namespace is opened. `using namespace axiam;` alongside it "
        "makes names the two share -- OpaqueEnrollment is one -- ambiguous, and the "
        "resulting diagnostic (\"parse error in template argument list\") points at the "
        "use site rather than the directive.", "", ))
    out.append("using namespace axiam::management;")
    out.append("")

    # ---- Pass A: every model round-trips ---------------------------------
    models = 0
    for name, rendered, _fields in modelled_ordered():
        example = example_for(name)
        if not isinstance(example, dict) or not example:
            # A model with no properties has nothing to lose in a round trip, and an
            # equality assertion over two empty objects asserts nothing. Skipped rather
            # than emitted as a passing tautology.
            continue
        models += 1
        out.append(f'AXIAM_TEST("management model {rendered} round-trips without losing a field") {{')
        out.append("    const auto wire = nlohmann::json::parse(")
        out.append("        " + cpp_raw_string(json.dumps(example, sort_keys=True)) + ");")
        out.append("")
        out.append(f"    const auto value = wire.get<{rendered}>();")
        out.append("    const nlohmann::json encoded = value;")
        out.extend(comment(
            "Exact equality, not \"the fields I remembered to check\". The wire object "
            "above carries every property the spec declares, so a dropped field and an "
            "invented one both fail here.", "    "))
        out.append("    AXIAM_CHECK(encoded == wire);")
        out.append("")
        out.extend(comment(
            "And encoding is a fixed point -- a second pass changes nothing.", "    "))
        out.append(f"    const nlohmann::json again = encoded.get<{rendered}>();")
        out.append("    AXIAM_CHECK(again == encoded);")
        out.append("}")
        out.append("")

    # ---- Pass B: every enum, both directions -----------------------------
    enums = 0
    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS:
            continue
        values = enum_values(name)
        if not values:
            continue
        enums += 1
        fn = f"{snake(rendered)}_from_wire"
        out.append(f'AXIAM_TEST("management enum {rendered} maps every value both ways") {{')
        for v in values:
            member = f"{rendered}::{enum_value(v)}"
            out.append(f'    AXIAM_CHECK(to_wire({member}) == "{v}");')
            out.append(f'    AXIAM_CHECK({fn}("{v}") == {member});')
        out.append("")
        out.extend(comment(
            "An unrecognised value is REPORTED. Mapping it to whichever enumerator "
            "happens to be first would turn a server newer than this SDK into silently "
            "wrong data rather than an error a caller can act on.", "    "))
        out.append("    bool reported = false;")
        out.append("    try {")
        out.append(f'        (void) {fn}("__not_a_{snake(rendered)}__");')
        out.append("    } catch (const std::invalid_argument&) {")
        out.append("        reported = true;")
        out.append("    }")
        out.append("    AXIAM_CHECK(reported);")
        out.append("")
        out.extend(comment(
            "The JSON hooks must agree with the wire functions, or a model carrying "
            "this enum encodes differently from the enum itself.", "    "))
        first = f"{rendered}::{enum_value(values[0])}"
        out.append(f"    const nlohmann::json j = {first};")
        out.append(f'    AXIAM_CHECK(j.get<std::string>() == "{values[0]}");')
        out.append(f"    AXIAM_CHECK(j.get<{rendered}>() == {first});")
        out.append("}")
        out.append("")

    # ---- Pass C: re-scoping returns a NEW handle -------------------------
    scopes = 0
    for namespace, nsdef in REGISTRY["namespaces"].items():
        first_op = None
        for opname, op in nsdef["operations"].items():
            if not [p for p in op_params(namespace, op) if p["kind"] == "body"]:
                first_op = (opname, op)
                break
        if first_op is None:
            continue
        opname, op = first_op
        template = op["path"]
        scopes += 1
        args = []
        pre = []
        for prm in op_params(namespace, op):
            if prm["kind"] == "path":
                args.append(f'"{EXAMPLE_UUID}"')
            elif prm["kind"] == "query" and prm["required"]:
                args.append('"example"')
        call_args = ", ".join(args)
        body = example_response(op)
        fixture_body = cpp_raw_string(json.dumps(body)) if body is not None else '""'
        status = "200" if body is not None else "204"

        # Both scopers, always. Testing only the one this route happens to substitute
        # would leave the other of the pair uncalled for every namespace -- 24 functions
        # nothing exercises -- and the inert case is worth an assertion in its own right:
        # an override for an identifier the route does not take must change nothing.
        rescoped = template.replace("{org_id}", OTHER_ORG).replace("{tenant_id}", OTHER_TENANT)
        expected_scoped = re.sub(r"\{[^}]+\}", EXAMPLE_UUID, rescoped)
        takes_either = "{org_id}" in template or "{tenant_id}" in template

        out.append(f'AXIAM_TEST("management {namespace}: re-scoping returns a new handle '
                   f'(§27.4 rule 3)") {{')
        out.append(f"    auto fixture = axtest::mgmt::signed_in_two({status}, {fixture_body},")
        out.append(f"                                              {status}, {fixture_body});")
        out.append("    auto mgmt = fixture.client.management();")
        out.append(f"    auto handle = mgmt.{method(namespace)}();")
        out.append("")
        out.extend(comment(
            "The re-scoped handle is a DIFFERENT object. On a management surface a "
            "handle that mutated in place would not merely read the wrong tenant -- an "
            "unrelated code path re-scoping a shared handle would WRITE to it.", "    "))
        out.append(f'    auto elsewhere = handle.in_org("{OTHER_ORG}")'
                   f'.for_tenant("{OTHER_TENANT}");')
        for line in pre:
            out.append("    " + line)
        out.append(f"    (void) elsewhere.{method(opname)}({call_args});")
        if takes_either:
            out.extend(comment("This route substitutes at least one of the two.", "    "))
        else:
            out.extend(comment(
                "This route substitutes NEITHER identifier, so the override is inert and "
                "the path is unchanged -- which is the assertion.", "    "))
        out.append("    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "
                   f'"{expected_scoped}");')
        out.append("")
        out.extend(comment("The original still points where it did.", "    "))
        out.append(f"    (void) handle.{method(opname)}({call_args});")
        out.append("    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "
                   f'"{expected_path(op)}");')
        out.append("}")
        out.append("")

    # ---- Pass D: client.<ns>() and client.management().<ns>() agree ----
    equivalents = 0
    for namespace, nsdef in REGISTRY["namespaces"].items():
        first_op = None
        for opname, op in nsdef["operations"].items():
            if not [p for p in op_params(namespace, op) if p["kind"] == "body"]:
                first_op = (opname, op)
                break
        if first_op is None:
            continue
        opname, op = first_op
        equivalents += 1

        args = []
        for prm in op_params(namespace, op):
            if prm["kind"] == "path":
                args.append(f'"{EXAMPLE_UUID}"')
            elif prm["kind"] == "query" and prm["required"]:
                args.append('"example"')
        call_args = ", ".join(args)
        body = example_response(op)
        fixture_body = cpp_raw_string(json.dumps(body)) if body is not None else '""'
        status = "200" if body is not None else "204"

        out.append(f'AXIAM_TEST("management {namespace}: client.{method(namespace)}() and '
                   f'management().{method(namespace)}() are equivalent (§27.2 rule 4)") {{')
        out.append(f"    auto fixture = axtest::mgmt::signed_in_two({status}, {fixture_body},")
        out.append(f"                                              {status}, {fixture_body});")
        out.append("")
        out.extend(comment(
            "§27.2 rule 4: \"where an SDK offers both, the two MUST return equivalent "
            "handles\". Equivalent means the same request, not merely the same type -- so "
            "this compares the method and path each actually put on the wire.", "    "))
        out.append(f"    (void) fixture.client.{method(namespace)}()"
                   f".{method(opname)}({call_args});")
        out.append("    const auto direct_method = fixture.state->last().method;")
        out.append("    const auto direct_path = "
                   "axtest::mgmt::path_of(fixture.state->last().url);")
        out.append("")
        out.append(f"    (void) fixture.client.management().{method(namespace)}()"
                   f".{method(opname)}({call_args});")
        out.append("    AXIAM_CHECK(fixture.state->last().method == direct_method);")
        out.append("    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "
                   "direct_path);")
        out.append(f'    AXIAM_CHECK(direct_path == "{expected_path(op)}");')
        out.append("}")
        out.append("")

    out.extend(comment(
        f"§27.9: {models} models, {enums} enums and {scopes} namespaces are covered "
        "above.\n\n"
        "Counted from the test registry rather than restated as a literal on both "
        "sides -- a case dropped by a bad regeneration would still satisfy a "
        "tautology, and fails this instead."))
    out.append('AXIAM_TEST("the generated model suite covers every model, enum and namespace") {')
    out.append("    int round_trips = 0;")
    out.append("    int enum_maps = 0;")
    out.append("    int rescopes = 0;")
    out.append("    int equivalents = 0;")
    out.append("    for (const auto& test : axtest::registry()) {")
    out.append('        if (test.name.find("round-trips without losing a field") != std::string::npos) {')
    out.append("            ++round_trips;")
    out.append('        } else if (test.name.find("maps every value both ways") != std::string::npos) {')
    out.append("            ++enum_maps;")
    out.append('        } else if (test.name.find("re-scoping returns a new handle") != std::string::npos) {')
    out.append("            ++rescopes;")
    out.append('        } else if (test.name.find("are equivalent") != std::string::npos) {')
    out.append("            ++equivalents;")
    out.append("        }")
    out.append("    }")
    out.append(f"    AXIAM_CHECK(round_trips == {models});")
    out.append(f"    AXIAM_CHECK(enum_maps == {enums});")
    out.append(f"    AXIAM_CHECK(rescopes == {scopes});")
    out.append(f"    AXIAM_CHECK(equivalents == {equivalents});")
    out.append("}")
    out.append("")
    out.append("}  // namespace")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build() -> dict[Path, str]:
    """Every file this generator owns, keyed by absolute path."""
    files = {
        MODELS_HPP: emit_models_header(),
        JSON_HPP: emit_json_header(),
        API_HPP: emit_api_header(),
        MODELS_CPP: emit_models_source(),
        OPS_CPP: emit_ops_source(),
        TEST_CPP: emit_test(),
        MODELS_TEST_CPP: emit_models_test(),
    }
    return {ROOT / path: text for path, text in files.items()}


def main() -> int:
    """Write (or, with ``--check``, verify) the generated §27 surface."""
    # Reject an unrecognised flag rather than ignoring it. The failure this
    # guards against is a CI job that means to VERIFY and instead REGENERATES
    # silently — a typo in the flag would turn the drift gate into a no-op that
    # reports success, which is the one outcome worse than no gate at all.
    unknown = [a for a in sys.argv[1:] if a != "--check"]
    if unknown:
        print(f"unrecognised argument(s): {' '.join(unknown)}", file=sys.stderr)
        print("usage: gen_management.py [--check]", file=sys.stderr)
        return 2

    check = "--check" in sys.argv
    files = build()

    if check:
        drifted = [p for p, text in sorted(files.items())
                   if not p.exists() or p.read_text() != text]
        if drifted:
            for path in drifted:
                print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
            print(
                "\nThe committed §27 surface disagrees with management-registry.json / "
                "openapi.json.\nRegenerate with `python3 scripts/gen_management.py` and "
                "commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"§27 surface is current ({len(files)} files).")
        return 0

    for path, text in sorted(files.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
