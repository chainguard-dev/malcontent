import "math"

private rule obfuscation_pythonSetup {
  strings:
    $if_distutils  = /from distutils.core import .{0,32}setup/
    $if_setuptools = /from setuptools import .{0,32}setup/
    $i_setuptools  = "import setuptools"
    $setup         = "setup("

    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"

  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_builtins: medium {
  meta:
    description = "Python library installer that references builtins"

  strings:
    $ref = "__builtins__" fullword

  condition:
    obfuscation_pythonSetup and $ref
}
