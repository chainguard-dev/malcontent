import "math"

private rule pythonSetup {
  strings:
    $if_distutils      = /from distutils.core import .{0,32}setup/
    $if_setuptools     = /from setuptools import .{0,32}setup/
    $i_setuptools      = "import setuptools"
    $setup             = "setup("
    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"

  condition:
    filesize < 131072 and $setup and any of ($i*) and none of ($not*)
}

rule py_no_fail: medium {
  meta:
    description = "Python code that hides exceptions"

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
    description = "PHP code that disables error reporting"

    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

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
