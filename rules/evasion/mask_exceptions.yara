
import "math"

private rule pythonSetup {
	strings:
		$i_distutils = "from distutils.core import setup"
		$i_setuptools = "setuptools"
		$setup = "setup(" fullword
	condition:
		filesize < 32768 and $setup and any of ($i*)
}

rule py_no_fail : notable {
	meta:
		description = "Python code that hides exceptions"
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
