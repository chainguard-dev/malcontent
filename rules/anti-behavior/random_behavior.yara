import "math"

private rule random_behavior_pythonSetup {
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

rule setuptools_random: critical {
  meta:
    description = "Python library installer that exhibits random behavior"
    filetypes   = "py"

  strings:
    $ref              = "import random"
    $not_easy_install = "pid = random.randint(0, sys.maxsize)"

  condition:
    random_behavior_pythonSetup and $ref and none of ($not*)
}

rule java_random: low {
  meta:
    description = "exhibits random behavior"
    filetypes   = "java"

  strings:
    $ref = "java/util/Random"

  condition:
    any of them
}

rule go_rand: medium {
  meta:
    description = "exhibits random behavior"
    filetypes   = "go"

  strings:
    $ref = "math/rand"

  condition:
    filesize < 100MB and any of them
}

rule rand_call: medium {
  meta:
    description = "exhibits random behavior"
    filetypes   = "c,pl,php"

  strings:
    $ref = "rand()"

  condition:
    filesize < 1MB and any of them
}

rule random: low {
  meta:
    description = "uses a random number generator"

  strings:
    $ref  = /\w{0,16}random\w{0,16}/ fullword
    $ref2 = /\w{0,16}Random\w{0,16}/ fullword

  condition:
    any of them
}
