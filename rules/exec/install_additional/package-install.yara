rule yum_installer: medium {
  meta:
    description              = "install software with yum"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"

    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

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
    description                          = "install software with apt"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
    hash_2024_scripts_install_locutus    = "1a80591019dea60785fff842da5f7347248e8ddf6a8a121d077210a06ba45e42"

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

    hash_2024_enumeration_deepce = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"

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
