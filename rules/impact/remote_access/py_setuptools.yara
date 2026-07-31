import "math"

private rule remote_access_pythonSetup {
  meta:
    filetypes = "py"

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
    $not_numba         = "https://github.com/numba/numba"

    $not_hopper1 = "PACKAGE_NAME = \"flashattn-hopper\""
    $not_hopper2 = "check_if_cuda_home_none(\"--fahopper\")"
    $not_hopper3 = "name=\"flashattn_hopper_cuda\","

  condition:
    filesize < 131072 and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_oslogin: medium {
  meta:
    description = "Python library installer that accesses user information"
    filetypes   = "py"

  strings:
    $oslogin = "os.login()"

  condition:
    remote_access_pythonSetup and any of them
}

rule setuptools_homedir: high {
  meta:
    description = "Python library installer that users home directory"
    filetypes   = "py"

  strings:
    $oslogin = "C:\\Users\\.{0,64}os.login()"

  condition:
    remote_access_pythonSetup and any of them
}

rule setuptools_cmd_exec: high {
  meta:
    description = "Python library installer that executes external commands"
    filetypes   = "py"

  strings:
    $f_os_system           = /os.system\([\"\'\.:\\\{\w\ \-\)\/]{0,64}/
    $f_os_popen            = /os.spopen\([\"\'\.:\{\w\\\ \-\)\/]{0,64}/
    $f_os_pstartfile       = /os.startfile\([\"\'\.:\\\{\w\ \-\)\/]{0,64}/
    $f_subprocess          = /subprocess.\w{0,32}\([\"\'\/\.:\\\{\w\ \-\)]{0,64}/
    $not_comment           = "Editable install to a prefix should be discoverable."
    $not_egg_info_requires = "os.path.join(egg_info_dir, 'requires.txt')"
    $not_requests          = "'Documentation': 'https://requests.readthedocs.io'"

    // These two lines are the back-to-back publish block of requests' setup.py.
    // Either command on its own is a one-liner malware readily copies in as
    // camouflage, so the pair is required as a set rather than member-by-member.
    $notgrp_publish_sdist = "python setup.py sdist bdist_wheel"
    $notgrp_publish_twine = "twine upload dist/*"

  condition:
    remote_access_pythonSetup and any of ($f*) and none of ($not_*) and not all of ($notgrp_publish*)
}

rule setuptools_cmd_exec_start: critical {
  meta:
    description = "Python library installer that executes the Windows 'start' command"
    filetypes   = "py"

  strings:
    $f_os_system    = /os.system\([f\"\']{0,2}start .{0,64}/
    $f_os_startfile = /os.startfile\([f\"\']{0,2}start .{0,64}/
    $f_os_popen     = /os.spopen\([f\"\']{0,2}start .{0,64}/
    $f_subprocess   = /subprocess.\w{0,32}\([f\"\']{0,2}start[,'" ]{1,3}.{0,64}/

  condition:
    remote_access_pythonSetup and any of ($f*)
}

rule setuptools_eval: medium {
  meta:
    description = "Python library installer that evaluates arbitrary code"
    filetypes   = "py"

  strings:
    $f_eval = /eval\([\"\'\/\w\,\.\ \-\)\(]{1,64}\)/ fullword

  condition:
    remote_access_pythonSetup and any of ($f*)
}

rule setuptools_eval_high: high {
  meta:
    description = "Python library installer that evaluates arbitrary code"
    filetypes   = "py"

  strings:
    $f_eval         = /eval\([\"\'\/\w\,\.\ \-\)\(]{1,64}\)/ fullword
    $not_namespaced = /eval\([\w\.\(\)\"\/\']{4,16}, [a-z]{1,6}[,\)]/ fullword

  // $not_namespaced describes a narrower spelling of the very eval() calls
  // $f_eval finds, so its presence only accounts for one of them. Compare
  // occurrence counts: fire only on an eval() no namespaced call accounts for.
  // $not_namespaced carries $f_eval's fullword so the two agree on where a call
  // starts and the counts stay comparable.

  condition:
    remote_access_pythonSetup and $f_eval and #f_eval > #not_namespaced
}

rule setuptools_exec: medium {
  meta:
    description = "Python library installer that executes arbitrary code"
    filetypes   = "py"

  strings:
    $f_exec = /exec\([\"\'\/\w\,\.\ \-\)\(]{1,64}\)/ fullword

    $not_hopper = "with open(\" hopper /__version__.py\") as fp:"

  condition:
    remote_access_pythonSetup and any of ($f*) and none of ($not*)
}

rule setuptools_exec_high: high {
  meta:
    description = "Python library installer that evaluates arbitrary code"
    filetypes   = "py"

  strings:
    $f_exec              = /exec\([\"\'\/\w\,\.\ \-\)\(]{1,64}\)/ fullword
    $not_apache          = "# Licensed under the Apache License, Version 2.0 (the \"License\")"
    $not_comment         = "Editable install to a prefix should be discoverable."
    $not_google          = /# Copyright [1-2][0-9]{3} Google Inc/
    $not_idna            = "A library to support the Internationalised Domain Names in Applications"
    $not_idna2           = "(IDNA) protocol as specified in RFC 5890 et.al."
    $not_pyspark_ioerror = "\"Failed to load PySpark version file for packaging. You must be in Spark's python dir.\""
    $not_requests        = "'Documentation': 'https://requests.readthedocs.io'"
    $not_test_egg_class  = "class TestEggInfo"

    // $f_exec matches inside both of these, so their presence only accounts for
    // one exec() call each rather than excusing the whole file. They are counted
    // below instead of being checked for presence, and $notsub_namespaced
    // carries $f_exec's fullword so the two agree on where a call starts.
    $notsub_pyspark_exec = "exec(open(\"pyspark/version.py\").read())"
    $notsub_namespaced   = /exec\([\w\.\(\)\"\/\']{4,16}, [a-z]{1,6}[,\)]/ fullword

  condition:
    remote_access_pythonSetup and $f_exec and none of ($not_*) and #f_exec > #notsub_namespaced + #notsub_pyspark_exec
}

rule setuptools_b64decode: suspicious {
  meta:
    description = "Python library installer that does base64 decoding"
    filetypes   = "py"

  strings:
    $base64 = "b64decode"

  condition:
    remote_access_pythonSetup and any of them
}

rule setuptools_preinstall: suspicious {
  meta:
    description = "Python library installer that imports a pre_install script"
    filetypes   = "py"

  strings:
    $preinstall    = "import preinstall"
    $pre_install   = "import pre_install"
    $f_preinstall  = "from preinstall"
    $f_pre_install = "from pre_install"

  condition:
    remote_access_pythonSetup and any of them
}

rule setuptools_b64encode: suspicious {
  meta:
    description = "Python library installer that does base64 encoding"
    filetypes   = "py"

  strings:
    $base64 = "b64encode"

  condition:
    remote_access_pythonSetup and any of them
}

rule setuptools_exec_powershell: critical windows {
  meta:
    description = "Python library installer that runs powershell"
    filetypes   = "py"

  strings:
    $powershell = "powershell" fullword
    $encoded    = "-EncodedCommand" fullword
    $window     = "WindowStyle Hidden" fullword

  condition:
    setuptools_cmd_exec and any of them
}

rule setuptools_os_path_exists: medium {
  meta:
    description = "Python library installer that checks for file existence"
    filetypes   = "py"

  strings:
    $ref                   = /[\w\.]{0,8}path.exists\([\"\'\w\ \-\)\/]{0,32}/
    $not_egg_info_requires = "os.path.join(egg_info_dir, 'requires.txt')"
    $not_pyspark_exec      = "exec(open(\"pyspark/version.py\").read())"
    $not_pyspark_ioerror   = "\"Failed to load PySpark version file for packaging. You must be in Spark's python dir.\""

  condition:
    remote_access_pythonSetup and $ref and none of ($not*)
}

rule setuptools_excessive_bitwise_math: critical {
  meta:
    description = "Python library installer that makes heavy use of bitwise math"
    filetypes   = "py"

  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/

  condition:
    remote_access_pythonSetup and #x > 20
}
