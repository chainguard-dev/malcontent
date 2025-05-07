private rule reverse_probably_js {
  strings:
    $f_Array     = "Array.prototype" fullword
    $f_async     = "async function"
    $f_await     = "await"
    $f_catch     = "} catch"
    $f_class     = "@class"
    $f_const     = /\bconst\s/
    $f_define    = "define("
    $f_false     = "false);"
    $f_function  = /function\(\w{0,32}\)/
    $f_function2 = "function()"
    $f_method    = "@method"
    $f_namespace = "@namespace"
    $f_Object    = "Object."
    $f_param     = "@param"
    $f_private   = "@private"
    $f_promise   = "Promise"
    $f_prototype = ".prototype"
    $f_require   = "require("
    $f_return    = /\breturn\s/
    $f_Run       = ".Run("
    $f_run       = ".run("
    $f_strict    = " === "
    $f_this      = "this."
    $f_this2     = "this["
    $f_true      = "true);"
    $f_try       = "try {"
    $f_var       = /\bvar\s/

    $not_asyncio           = "await asyncio"
    $not_class             = /class \w{1,32}\(/ fullword
    $not_def               = /def [a-zA-Z_][a-zA-Z0-9_]{1,32} \(/ ascii
    $not_equals_comment    = "// ==="
    $not_error             = "err error"
    $not_header            = /^#ifndef\s/
    $not_header2           = /^#define\s/
    $not_header3           = /^#include\s/
    $not_import            = /^import \(/
    $not_package           = /^package\s/
    $not_self_assert_equal = "self.assertEqual("
    $not_struct            = /^type \w{1,32} struct \{/ fullword
    $not_typedef           = "typedef typename"

  condition:
    filesize < 5MB and 4 of ($f*) and none of ($not*)
}

rule string_reversal: medium {
  meta:
    description = "reverses strings"

  strings:
    $ref = ".reverse().join(\"\")"

  condition:
    any of them
}

rule function_reversal: medium {
  meta:
    description = "reversed function definition"

  strings:
    $ref = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/

  condition:
    filesize < 1MB and any of them
}

rule js_reversal: critical {
  meta:
    description = "multiple reversed javascript calls"

  strings:
    $ref  = /n.{0,3}o.{0,3}i.{0,3}t.{0,3}c.{0,3}n.{0,3}u.{0,3}f/
    $ref2 = /n.{0,3}r.{0,3}u.{0,3}t.{0,3}e.{0,3}r/

  condition:
    reverse_probably_js and filesize < 1MB and all of them
}
