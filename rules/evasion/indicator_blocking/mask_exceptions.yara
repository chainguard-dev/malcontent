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
    filesize < 131072 and $setup and any of ($i*) and none of ($not*)
}

rule py_no_fail: notable {
  meta:
    description                              = "Python code that hides exceptions"
    hash_2023_grandmask_3_13_setup           = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
    hash_2023_libgrandrandomintel_3_58_setup = "cd211e0f8d84100b1b4c1655e913f40a76beaacc482e751e3a7c7ed126fe1a90"
    hash_2023_py_guigrand_4_67_setup         = "4cb4b9fcce78237f0ef025d1ffda8ca8bc79bf8d4c199e4bfc6eff84ce9ce554"

  strings:
    $e_short = /except:.{0,4}pass/ fullword
    $e_long  = /except Exception as.{0,8}pass/ fullword

  condition:
    any of them
}

rule setuptools_no_fail: suspicious {
  meta:
    description = "Python library installer that hides exceptions"

  condition:
    pythonSetup and py_no_fail
}

rule php_disable_errors: medium {
  meta:
    description                  = "PHP code that disables error reporting"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_untitled   = "39b2fd6b4b2c11a9cbfc8efbb09fc14d502cde1344f52e1269228fc95b938621"
    hash_2023_0xShell_wesoori    = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

  strings:
    $err_rep       = "error_reporting(0)"
    $log_errs      = /ini_set\(\Wlog_errors\W{0,4}0/
    $display_0     = /ini_set\(\Wdisplay_errors\W{0,4}0/
    $error_log     = /ini_set\(\Werror_log\W{0,4}NULL/
    $display_off   = /ini_set\(\Wdisplay_errors\W{0,4}Off/
    $display_false = /ini_set\(\Wdisplay_errors\W{0,4}FALSE/

  condition:
    1 of them
}
