"""Validate a document against one of the published JSON schemas.

Not a general JSON Schema implementation. The four published schemas use fifteen
keywords between them, this covers those, and anything outside that set is
REPORTED rather than skipped — a checker that silently ignored an unknown
keyword would be weaker than the schema it checks, and its silence would read
as a pass (D1156).

It lives beside `check.sh` rather than under `scripts/` because it ships with
the harness: the public tree carries `examples/` and not the private scripts,
so a helper the harness imports has to travel with it.

One copy, all four schemas, both directions — outputs the runtime PRINTS
(D1156) and documents a stranger validates BEFORE the runtime sees them
(D1157). A second copy would be free to agree with this one by luck.
"""
import re

KNOWN = {"type", "properties", "required", "items", "enum", "const", "$ref",
         "additionalProperties", "pattern", "minimum", "maximum", "maxLength",
         "minItems", "propertyNames", "patternProperties", "description", "$defs", "$schema", "$id",
         "title", "$comment", "anyOf", "allOf", "if", "then", "else"}

TYPES = {"object": dict, "array": list, "string": str, "boolean": bool,
         "number": (int, float), "integer": int, "null": type(None)}


def errors(doc, schema, defs, path=""):
    """Return [(path, message)] for every way `doc` fails `schema`."""
    out = []
    unknown = set(schema) - KNOWN
    if unknown:
        out.append((path, "this checker does not implement %s" % sorted(unknown)))

    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            return out + [(path, "unsupported $ref %s" % ref)]
        return out + errors(doc, defs[ref[len("#/$defs/"):]], defs, path)

    # allOf / if-then: how the state schema says "a body's shape depends on the
    # event TYPE". Without them a checker either refuses the file outright or —
    # far worse — passes over the one rule that constrains the payload.
    for sub in schema.get("allOf", []):
        out += errors(doc, sub, defs, path)
    if "if" in schema:
        branch = "then" if not errors(doc, schema["if"], defs, path) else "else"
        if branch in schema:
            out += errors(doc, schema[branch], defs, path)

    # anyOf: the document must satisfy at least one branch. Reporting every
    # branch's complaint would bury the real one, so a failure says only that
    # nothing matched, with the branch count.
    if "anyOf" in schema:
        if not any(not errors(doc, b, defs, path) for b in schema["anyOf"]):
            out.append((path, "matches none of the %d published alternatives"
                        % len(schema["anyOf"])))
        return out

    if "type" in schema:
        want = schema["type"]
        want = want if isinstance(want, list) else [want]
        ok = False
        for w in want:
            t = TYPES.get(w)
            if t is None:
                out.append((path, "unknown type %s" % w))
                ok = True
                break
            # bool is a subclass of int in Python; a boolean is not an integer here.
            if w in ("number", "integer") and isinstance(doc, bool):
                continue
            if isinstance(doc, t):
                ok = True
        if not ok:
            return out + [(path, "is %s, schema says %s"
                           % (type(doc).__name__, want))]

    if "enum" in schema and doc not in schema["enum"]:
        out.append((path, "%r is not one of %s" % (doc, schema["enum"])))
    if "const" in schema and doc != schema["const"]:
        out.append((path, "%r is not the const %r" % (doc, schema["const"])))
    if "pattern" in schema and isinstance(doc, str) and not re.search(schema["pattern"], doc):
        out.append((path, "%r does not match %s" % (doc, schema["pattern"])))
    for bound, cmp_, word in (("minimum", lambda a, b: a < b, "below"),
                              ("maximum", lambda a, b: a > b, "above")):
        if bound in schema and isinstance(doc, (int, float)) and not isinstance(doc, bool):
            if cmp_(doc, schema[bound]):
                out.append((path, "%s is %s the %s %s" % (doc, word, bound, schema[bound])))

    if "maxLength" in schema and isinstance(doc, str) and len(doc) > schema["maxLength"]:
        out.append((path, "is %d characters, the published maximum is %d"
                    % (len(doc), schema["maxLength"])))
    if "minItems" in schema and isinstance(doc, list) and len(doc) < schema["minItems"]:
        out.append((path, "holds %d items, the published minimum is %d"
                    % (len(doc), schema["minItems"])))

    if isinstance(doc, dict):
        # propertyNames constrains the KEYS. It is how the schemas say "every
        # capability id is an identifier" for an open map, and skipping it would
        # leave the one rule those maps actually carry unread.
        if "propertyNames" in schema:
            for k in doc:
                for p2, msg in errors(k, schema["propertyNames"], defs, path):
                    out.append((p2, "property name %r: %s" % (k, msg)))
        for prop in schema.get("required", []):
            if prop not in doc:
                out.append((path, "required property %r is absent" % prop))
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties")
        # patternProperties is how a closed object still admits a family of keys —
        # here the `x-` escape the document schemas publish for "deliberately not
        # runtime data". Unread, a closed block would reject every document that
        # uses the escape it advertises.
        patterns = schema.get("patternProperties", {})
        for k, v in doc.items():
            sub = path + "/" + k if path else k
            if k in props:
                out += errors(v, props[k], defs, sub)
                continue
            hit = next((ps for pat, ps in patterns.items() if re.search(pat, k)), None)
            if hit is not None:
                out += errors(v, hit, defs, sub)
            elif isinstance(extra, dict):
                # An open map (bindings, heads, outcomes, requirements): the keys
                # are free, the VALUES are constrained.
                out += errors(v, extra, defs, sub)
            elif extra is False:
                out.append((sub, "is not a key this block admits"))
            # else: growth is allowed. `versioning.md` promises outputs may grow
            # fields and no published schema closes an object, so the two agree.
    if isinstance(doc, list) and "items" in schema:
        for i, v in enumerate(doc):
            out += errors(v, schema["items"], defs, "%s/%d" % (path, i))
    return out


def selftest():
    """Documents that MUST fail, and the complaint if any of them passes.

    Everything this module produces is a NEGATIVE result, and a negative result
    that cannot be told from a broken checker is worth nothing: replace `errors`
    with `return []` and every caller keeps printing PASS. So the callers ask
    for this and report what it says.
    """
    schema = {"type": "object", "required": ["a"],
              "properties": {"a": {"enum": ["x"]}, "n": {"type": "integer"}}}
    bad = []
    for name, doc, unread in (
        ("a value outside its enum", {"a": "not-x"}, "enum"),
        ("a missing required property", {}, "required"),
        ("a string where an integer is published", {"a": "x", "n": "7"}, "type"),
    ):
        if not errors(doc, schema, {}):
            bad.append("the checker itself is broken: it accepted %s, so every PASS "
                       "it prints is meaningless (%s went unread)" % (name, unread))
    return bad
