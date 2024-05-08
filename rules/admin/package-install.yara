
rule yum_installer : notable {
  meta:
    description = "install software with yum"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $val = /yum install[ \w\-\_%]{0,32}/
  condition:
    $val
}

rule dnf_installer : notable {
  meta:
    description = "install software with dnf"
  strings:
    $val = /dnf install[ \w\-\_%]{0,32}/
  condition:
    $val
}

rule rpm_installer : notable {
  meta:
    description = "install software with rpm"
    hash_2023_Unix_Coinminer_Xanthe_7ea1 = "7ea112aadebb46399a05b2f7cc258fea02f55cf2ae5257b331031448f15beb8f"
  strings:
    $val = /rpm -i[ \w\-\_%]{0,32}/
  condition:
    $val
}

rule apt_installer : notable {
  meta:
    description = "install software with apt"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"
  strings:
    $val = /apt install[ \w\-\_%]{0,32}/
  condition:
    $val
}

rule apt_get_installer : notable {
  meta:
    description = "install software with apt-get"
    hash_2019_lib_restclient = "c9b67d3d9ef722facd1abce98bd7d80cec1cc1bb3e3a52c54bba91f19b5a6620"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
  strings:
    $val = /apt-get install[ \w\-\_%]{0,32}/
    $foo = "install foo"
  condition:
    $val and not $foo
}

rule apk_installer : notable {
  meta:
    description = "install software with APK"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $val = /apk add[ \w\-\_%]{0,32}/
  condition:
    $val
}

rule pip_installer_regex : notable {
  meta:
    description = "Includes 'pip install' command for installing Python modules"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2022_2022_requests_3_0_0_README = "150fd62db4024e240040be44b32d7ce98df80ab86dfd564a173cd231f2254abc"
  strings:
    $regex = /pip[3 \'\"]{0,5}install[ \'\"\w\-\_%]{0,32}/
  condition:
    any of them
}
