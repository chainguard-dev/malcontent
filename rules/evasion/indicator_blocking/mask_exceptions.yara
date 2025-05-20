include "rules/global/global.yara"

import "math"

rule py_no_fail: medium {
  meta:
    description = "Python code that hides exceptions"
    filetypes   = "py"

  strings:
    $e_short = /except:.{0,4}pass/ fullword
    $e_long  = /except Exception as.{0,8}pass/ fullword

  condition:
    any of them
}

rule setuptools_no_fail: suspicious {
  meta:
    description = "Python library installer that hides exceptions"
    filetypes   = "py"

  condition:
    global_python_setup and py_no_fail
}

rule php_disable_errors: medium {
  meta:
    description = "PHP code that disables error reporting"
    filetypes   = "php"

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
