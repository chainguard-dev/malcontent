import "math"

private rule pythonSetup {
  strings:
    $if_distutils  = /from distutils.core import .{0,32}setup/
    $if_setuptools = /from setuptools import .{0,32}setup/
	$i_setuptools = "import setuptools"
    $setup        = "setup("

    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"

  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_random: critical {
  meta:
    description = "Python library installer that exhibits random behavior"

  strings:
    $ref              = "import random"
    $not_easy_install = "pid = random.randint(0, sys.maxsize)"

  condition:
    pythonSetup and $ref and none of ($not*)
}
