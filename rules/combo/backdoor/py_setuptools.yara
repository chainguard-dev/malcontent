import "math"

private rule pythonSetup {
  strings:
    $i_distutils = "from distutils.core import setup"
    $i_setuptools = "setuptools"
    $setup = "setup("
  condition:
    filesize < 2097152 and $setup and any of ($i*)
}

rule setuptools_cmd_exec : suspicious {
  meta:
    description = "Python library installer that executes external commands"
  strings:
    $os_system = /os.system\([\"\'\w\ \-\)\/]{0,64}/
    $os_popen = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
    $subprocess = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
  condition:
    pythonSetup and any of them
}

rule setuptools_eval : critical {
  meta:
    description = "Python library installer that evaluates arbitrary code"
  strings:
    $f_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
    $f_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
  condition:
    pythonSetup and any of ($f*)
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
  condition:
    pythonSetup and $ref
}

rule setuptools_excessive_bitwise_math : critical {
  meta:
    description = "Python library installer that makes heavy use of bitwise math"
  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/
  condition:
    pythonSetup and #x > 20
}
