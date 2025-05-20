include "rules/global/global.yara"

import "math"

rule unmarshal_py_marshal: medium {
  meta:
    description = "reads python values from binary content"
    filetypes   = "py"

  strings:
    $ref = "import marshal"

  condition:
    filesize < 128KB and any of them
}

rule setuptools_py_marshal: suspicious {
  meta:
    description = "Python library installer that reads values from binary content"
    filetypes   = "py"

  condition:
    global_python_setup and unmarshal_py_marshal
}
