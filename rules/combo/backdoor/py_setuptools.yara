import "math"

rule setuptools_cmd_exec : suspicious {
  meta:
    description = "Python library installer that executes external commands"
    hash_2022_laysound_4_5_2_setup = "4465bbf91efedb996c80c773494295ae3bff27c0fff139c6aefdb9efbdf7d078"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
  strings:
    $setup = "setup(" fullword
    $setuptools = "setuptools"
    $distutils = "distutils"
    $s_sys_val = /os.system\([\"\'\w\ \-\)\/]{0,64}/
    $s_subprocess_val = /subprocess.\w{0,32}\([\"\'\/\w\ \-\)]{0,64}/
    $s_import = "import subprocess"
  condition:
    $setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_eval : critical {
  meta:
    description = "Python library installer that evaluates arbitrary code"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2023_requet_2_28_1_setup = "9438107245ebfba792dfa95f7d551392831c20adbcac7d3176797f0f00683ab0"
    hash_2023_zproxy_1_0_setup = "f3d7eec1ae2eba61715fd0652fa333acc2e4c0d517579392043880aa2f158b62"
  strings:
    $setup = "setup(" fullword
    $setuptools = "setuptools"
    $distutils = "distutils"
    $s_sys_val = /eval\([\"\'\w\ \-\)\/]{0,64}/ fullword
    $s_subprocess_val = /exec\([\"\'\/\w\ \-\)]{0,64}/ fullword
  condition:
    $setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_url_access : suspicious {
  meta:
    description = "Python library installer that accesses external URLs"
    hash_2022_laysound_4_5_2_setup = "4465bbf91efedb996c80c773494295ae3bff27c0fff139c6aefdb9efbdf7d078"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2022_selenuim_4_4_2_setup = "5c5e1d934dbcbb635f84b443bc885c9ba347babc851cd225d2e18eadc111ecf0"
  strings:
    $setup = "setup(" fullword
    $setuptools = "setuptools"
    $distutils = "distutils"
    $s_requests = /requests.get\([\"\'\w\ \-\)\/]{0,64}/
    $s_urlopen = /urlopen\([\"\'\w\ \-\)\/]{0,64}/
  condition:
    $setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_random : critical {
  meta:
    description = "Python library installer that exhibits random behavior"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
  strings:
    $setup = "setup(" fullword
    $setuptools = "setuptools"
    $distutils = "distutils"
    $s_sys_val = "import random" fullword
  condition:
    $setup and ($setuptools or $distutils) and any of ($s_*)
}

rule setuptools_builtins : notable {
  meta:
    description = "Python library installer that directly references builtins"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
  strings:
    $setup = "setup(" fullword
    $setuptools = "setuptools"
    $distutils = "distutils"
    $s_sys_val = "__builtins__" fullword
  condition:
    $setup and ($setuptools or $distutils) and any of ($s_*)
}
