import "math"

private rule pySetup {
  strings:
    $i_distutils    = "from distutils.core import setup"
    $i_setuptools   = "setuptools"
    $setup          = "setup("
    $not_setuptools = "setuptools.command"

  condition:
    // "setuptools" is a substring of "setuptools.command", so a single
    // setuptools.command mention used to disable the whole rule; count past it
    filesize < 2097152 and $setup and ($i_distutils or #i_setuptools > #not_setuptools)
}

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
    pySetup and unmarshal_py_marshal
}
