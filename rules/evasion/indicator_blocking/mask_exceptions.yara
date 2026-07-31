import "math"

private rule indicator_blocking_pythonSetup {
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
    // ">>> setup(", "setup(**config.todict()" and "\"setup(name=" each contain a
    // literal "setup(", so compare counts: a doctest or quoted example cancels
    // only its own occurrence and a real setup() call still registers. The two
    // import markers are not "setup(" matches and stay membership tests.
    filesize < 131072 and #setup > #not_setup_example + #not_setup_todict + #not_setup_quoted and any of ($i*) and none of ($not_import_quoted, $not_distutils)
}

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
    indicator_blocking_pythonSetup and py_no_fail
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
