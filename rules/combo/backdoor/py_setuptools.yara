import "math"

private rule pythonSetup {
  strings:
    $i_distutils = "from distutils.core import setup"
    $i_setuptools = "from setuptools import setup"
	$setup = "setup("

	$not_setup_example = ">>> setup("
	$not_setup_todict = "setup(**config.todict()"
	$not_import_quoted = "\"from setuptools import setup"
	$not_setup_quoted = "\"setup(name="
	$not_distutils = "from distutils.errors import"
  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_cmd_exec : suspicious {
  meta:
    description = "Python library installer that executes external commands"
  strings:
    $f_os_system = /os.system\([\"\'\w\ \-\)\/]{0,64}/
    $f_os_popen = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
    $f_subprocess = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
    $not_egg_info_requires = "os.path.join(egg_info_dir, 'requires.txt')"
    $not_sample = "# now run 'sample' with the prefix on the PYTHONPATH"
  condition:
    pythonSetup and any of ($f*) and none of ($not*)
}

rule setuptools_eval : critical {
  meta:
    description = "Python library installer that evaluates arbitrary code"
  strings:
    $f_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
    $f_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
    $not_comment = "Editable install to a prefix should be discoverable."
    $not_test_egg_class = "class TestEggInfo"
  condition:
    pythonSetup and any of ($f*) and none of ($not*)
}

rule setuptools_b64decode : suspicious {
  meta:
    description = "Python library installer that does base64 decoding"
  strings:
    $base64 = "b64decode"
  condition:
    pythonSetup and any of them
}

rule setuptools_exec_powershell : critical {
  meta:
    description = "Python library installer that runs powershell"
  strings:
    $powershell = "powershell" fullword
    $encoded = "-EncodedCommand" fullword
    $window = "WindowStyle Hidden" fullword
  condition:
    setuptools_cmd_exec and any of them
}

rule setuptools_os_path_exists : notable {
  meta:
    description = "Python library installer that checks for file existence"
  strings:
    $ref = /[\w\.]{0,8}path.exists\([\"\'\w\ \-\)\/]{0,32}/
    $not_egg_info_requires = "os.path.join(egg_info_dir, 'requires.txt')"
  condition:
    pythonSetup and $ref and none of ($not*)
}

rule setuptools_excessive_bitwise_math : critical {
  meta:
    description = "Python library installer that makes heavy use of bitwise math"
  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/
  condition:
    pythonSetup and #x > 20
}
