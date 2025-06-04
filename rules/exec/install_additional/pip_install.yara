import "math"

rule pip_installer_known_good: low {
  meta:
    description = "Installs software using pip from python"

  strings:
    $distro = /pip3{0,1} install (distro|mock|pyopenssl|colorama|twisted)/ fullword

  condition:
    any of them
}

rule pip_installer_variable: medium {
  meta:
    description = "Installs software using pip from python"

  strings:
    $ref = /pip3{0,1}[ \'\"\,]{0,5}install[ \'\"\,]{0,5}[\$\%\{}][\w\-\_\}]{0,32}/

  condition:
    $ref and not pip_installer_known_good
}

rule pip_installer: medium {
  meta:
    description = "Installs software using pip from python"

    filetypes = "bash,py,pyc,sh,zsh"

  strings:
    $ref = /pip3{0,1}[ \'\"\,]{0,5}install[ \'\"\,]{0,5}[\w\-\_\%]{0,32}/

  condition:
    $ref and not pip_installer_known_good and not pip_installer_variable
}

rule pip_installer_fernet: critical {
  meta:
    description = "Installs fernet crypto package using pip"
    ref         = "https://checkmarx.com/blog/over-170k-users-affected-by-attack-using-fake-python-infrastructure/"
    filetypes   = "py,pyc"

  strings:
    $ref = /pip.{1,5}install.{1,4}fernet/

  condition:
    $ref
}

rule pip_installer_url: critical {
  meta:
    description = "Installs Python package from hardcoded URL"
    ref         = "https://checkmarx.com/blog/over-170k-users-affected-by-attack-using-fake-python-infrastructure/"
    filetypes   = "bash,py,pyc,sh,zsh"

  strings:
    $ref = /pip.{1,5}install.{1,4}https{0,1}:\/\/.{0,64}/

    $not_langchain_comment1 = "Please install the exllamav2 library with (cuda 12.1 is required)"
    $not_langchain_comment2 = "example : "
    $not_langchain_comment3 = "\"!python -m pip install https://github.com/turboderp/exllamav2/releases/download/v0.0.12/exllamav2-0.0.12+cu121-cp311-cp311-linux_x86_64.whl\""

  condition:
    filesize < 8192 and $ref and none of ($not*)
}

rule pip_installer_socket: critical {
  meta:
    description = "Installs socket library using pip"
    filetypes   = "py,pyc"

  strings:
    $ref = /pip.{1,5}install.{1,4}socket/

    $not_langchain_comment1 = "\"Please install it with `pip install websocket-client`.\""

  condition:
    $ref and none of ($not*)
}

rule pip_installer_requests: high {
  meta:
    description = "Installs requests library using pip"
    filetypes   = "py,pyc"

  strings:
    $ref = /pip.{1,5}install.{1,4}requests/

  condition:
    $ref
}

rule pip_installer_sus: high {
  meta:
    description = "Installs libraries using pip"
    filetypes   = "py,pyc"

  strings:
    $crypto  = "Crypto.Cipher"
    $urllib  = "urllib.request"
    $zipfile = "zipfile"
    $base64  = "base64"
    $json    = "json"
    $sqlite  = "sqlite3"

    $not_pypi_index = "testpack-id-lb001"

  condition:
    pip_installer and 4 of them and none of ($not*)
}
