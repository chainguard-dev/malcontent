rule yum_installer: medium {
  meta:
    description = "install software with yum"

  strings:
    $val = /yum install[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule dnf_installer: medium {
  meta:
    description = "install software with dnf"

  strings:
    $val = /dnf install[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule rpm_installer: medium {
  meta:
    description = "install software with rpm"

  strings:
    $val = /rpm -i[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule apt_installer: medium {
  meta:
    description = "install software with apt"

  strings:
    $val = /apt install[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule apt_get_installer: medium {
  meta:
    description = "install software with apt-get"

  strings:
    $val = /apt-get install[ \w\-\_%]{0,32}/
    $foo = "install foo"

  condition:
    $val and not $foo
}

rule apk_installer: medium {
  meta:
    description = "install software with APK"

  strings:
    $val = /apk add[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule sudo_installer_pkg: high macos {
  meta:
    description = "install software with installer"

  strings:
    $val = /sudo installer -pkg [\w\/\.\"\-]{0,32} -target [\w\/\.\"\-]{0,32}/

  condition:
    $val
}
