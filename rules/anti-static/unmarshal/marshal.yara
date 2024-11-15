import "math"

private rule pySetup {
  strings:
    $i_distutils    = "from distutils.core import setup"
    $i_setuptools   = "setuptools"
    $setup          = "setup("
    $not_setuptools = "setuptools.command"

  condition:
    filesize < 2097152 and $setup and any of ($i*) and none of ($not*)
}

rule py_marshal: medium {
  meta:
    description = "reads python values from binary content"

  strings:
    $ref = "import marshal"

  condition:
    filesize < 128KB and any of them
}

rule setuptools_py_marshal: suspicious {
  meta:
    description = "Python library installer that reads values from binary content"

  condition:
    pySetup and py_marshal
}
