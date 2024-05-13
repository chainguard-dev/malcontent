import "math"

private rule pythonSetup {
  strings:
    $i_distutils = "from distutils.core import setup"
    $i_setuptools = "setuptools"
    $setup = "setup("
  condition:
    filesize < 2097152 and $setup and any of ($i*)
}

rule py_no_fail : notable {
  meta:
    description = "Python code that hides exceptions"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
    hash_2023_libgrandrandomintel_3_58_setup = "cd211e0f8d84100b1b4c1655e913f40a76beaacc482e751e3a7c7ed126fe1a90"
    hash_2023_py_guigrand_4_67_setup = "4cb4b9fcce78237f0ef025d1ffda8ca8bc79bf8d4c199e4bfc6eff84ce9ce554"
  strings:
    $e_short = /except:.{0,4}pass/ fullword
    $e_long = /except Exception as.{0,8}pass/ fullword
  condition:
    any of them
}

rule setuptools_no_fail : suspicious {
  meta:
    description = "Python library installer that hides exceptions"
  condition:
    pythonSetup and py_no_fail
}
