
import "math"

rule setuptools_no_fail : suspicious {
	meta:
		description = "Python library installer that hides exceptions"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$e_val = /except:.{0,4}pass/ fullword
	condition:
		$setup and ($setuptools or $distutils) and $e_val
}

rule setuptools_no_fail2 : suspicious {
	meta:
		description = "Python library installer that hides exceptions"
	strings:
		$setup = "setup(" fullword

		$setuptools = "setuptools"
		$distutils = "distutils"

		$e_val = /except Exception as.{0,8}pass/ fullword
	condition:
		$setup and ($setuptools or $distutils) and $e_val
}