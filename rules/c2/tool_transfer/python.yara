private rule py_fetcher: medium {
  meta:
    description = "fetches content"
    filetypes   = "py"

  strings:
    $http_requests      = "requests.get" fullword
    $http_requests_post = "requests.post" fullword
    $http_urllib        = "urllib.request" fullword
    $http_urlopen       = "urlopen" fullword
    $git_git            = /git.Git\(.{0,64}/
    $http_curl          = "curl" fullword
    $http_wget          = "wget" fullword

  condition:
    any of them
}

private rule py_runner {
  meta:
    description = "runs programs"
    filetypes   = "py"

  strings:
    $os_system    = /os.system\([\"\'\w\ \-\)\/]{0,64}/
    $os_startfile = /os.startfile\([\"\'\w\ \-\)\/]{0,64}/
    $os_popen     = /os.spopen\([\"\'\w\ \-\)\/]{0,64}/
    $subprocess   = /subprocess.\w{1,32}\([\"\'\/\w\ \-\)]{0,64}/
    $system       = /system\([\"\'\w\ \-\)\/]{0,64}/

  condition:
    any of them
}

rule py_dropper: medium {
  meta:
    description = "may fetch, store, and execute programs"
    filetypes   = "py"

  strings:
    $open  = "open("
    $write = "write("

  condition:
    filesize < 16384 and $open and $write and py_fetcher and py_runner
}

rule py_arch_dropper: medium {
  meta:
    description = "fetches and executes program based on OS & architecture"
    filetypes   = "py"

  strings:
    $os_Linux    = "Linux" fullword
    $os_macOS    = "macOS" fullword
    $os_platform = "platform.system()"

    $arch_arm64   = "arm64" fullword
    $arch_x86     = "x86" fullword
    $arch_amd64   = "amd64" fullword
    $arch_machine = "platform.machine()"

    $download = "download" fullword

    $exec_run = "run" fullword

  condition:
    filesize < 1MB and any of ($os*) and any of ($arch*) and any of ($download*) and (any of ($exec*) or py_runner)
}

rule py_dropper_obfuscated: high {
  meta:
    description = "may fetch, obfuscate, store, and execute programs"
    filetypes   = "py"

  strings:
    $open      = "open("
    $write     = "write("
    $ob_base64 = "b64decode"
    $ob_codecs = "codecs.decode"

  condition:
    filesize < 16000 and $open and $write and any of ($ob_*) and py_fetcher and py_runner
}

rule py_dropper_tiny: high {
  meta:
    description = "may fetch, stores, and execute programs"
    filetypes   = "py"

  strings:
    $open  = "open("
    $write = "write("

  condition:
    filesize < 900 and $open and $write and py_fetcher and py_runner
}

rule py_dropper_chmod: high {
  meta:
    description = "fetch, stores, chmods, and execute programs"
    filetypes   = "py"

  strings:
    $chmod    = "chmod"
    $val_x    = "+x"
    $val_exec = "755"
    $val_rwx  = "777"
    $val_770  = "770"

  condition:
    filesize < 1MB and py_fetcher and py_runner and $chmod and any of ($val*)
}

private rule tool_transfer_pythonSetup {
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
    $not_dir           = "dist-packages/setuptools"
    $not_fetch         = "fetch_distribution"
    $not_hopper1       = "PACKAGE_NAME = \"flashattn-hopper\""
    $not_hopper2       = "check_if_cuda_home_none(\"--fahopper\")"
    $not_hopper3       = "name=\"flashattn_hopper_cuda\","

  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule setuptools_fetcher: suspicious {
  meta:
    description = "setuptools script that fetches content"
    filetypes   = "py"

  condition:
    tool_transfer_pythonSetup and py_fetcher
}

rule setuptools_fetch_run: critical {
  meta:
    description = "setuptools script that fetches and executes"
    filetypes   = "py"

  strings:
    $not_hopper1 = "PACKAGE_NAME = \"flashattn-hopper\""
    $not_hopper2 = "check_if_cuda_home_none(\"--fahopper\")"
    $not_hopper3 = "name=\"flashattn_hopper_cuda\","

  condition:
    setuptools_fetcher and py_runner and none of ($not*)
}

rule setuptools_dropper: critical {
  meta:
    description = "setuptools script that fetches, stores, and executes programs"
    filetypes   = "py"

  condition:
    tool_transfer_pythonSetup and py_dropper
}

rule dropper_imports: high {
  meta:
    description = "imports modules known to be used by Python droppers"
    filetypes   = "py"

  strings:
    $http         = "http"
    $import       = "import" fullword
    $l_base64     = "base64" fullword
    $l_platform   = "platform" fullword
    $l_os         = "os" fullword
    $l_subprocess = "subprocess" fullword
    $l_sys        = "sys" fullword
    $l_requests   = "requests" fullword

  condition:
    filesize < 4000 and $http and $import and 5 of ($l*)
}

rule oneline: high {
  meta:
    description = "fetch, stores, and execute programs"
    filetypes   = "py"

  strings:
    $urlopen = /\.write\(.{0,8}urlopen\("http.{0,128}\"\).read\(\)/

  condition:
    filesize < 512KB and any of them and py_fetcher and py_runner

}
