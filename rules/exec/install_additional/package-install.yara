rule yum_installer: medium {
  meta:
    description                         = "install software with yum"
    hash_2023_Downloads_6e35            = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi            = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

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
    description                          = "install software with rpm"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"

  strings:
    $val = /rpm -i[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule apt_installer: medium {
  meta:
    description                            = "install software with apt"
    hash_2023_Unix_Downloader_Rocke_6107   = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
    hash_2024_scripts_install_locutus      = "1a80591019dea60785fff842da5f7347248e8ddf6a8a121d077210a06ba45e42"
    hash_2024_static_demonizedshell_static = "b4e65c01ab90442cb5deda26660a3f81bd400c205e12605536483f979023aa15"

  strings:
    $val = /apt install[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule apt_get_installer: medium {
  meta:
    description              = "install software with apt-get"
    hash_2019_lib_restclient = "c9b67d3d9ef722facd1abce98bd7d80cec1cc1bb3e3a52c54bba91f19b5a6620"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"

  strings:
    $val = /apt-get install[ \w\-\_%]{0,32}/
    $foo = "install foo"

  condition:
    $val and not $foo
}

rule apk_installer: medium {
  meta:
    description                         = "install software with APK"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2024_enumeration_deepce        = "76b0bcdf0ea0b62cee1c42537ff00d2100c54e40223bbcb8a4135a71582dfa5d"

  strings:
    $val = /apk add[ \w\-\_%]{0,32}/

  condition:
    $val
}

rule sudo_installer_pkg: high macos {
  meta:
    description                         = "install software with installer"
  strings:
    $val = /sudo installer -pkg [\w\/\.\"\-]{0,32} -target [\w\/\.\"\-]{0,32}/
  condition:
    $val
}
