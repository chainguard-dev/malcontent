rule tar_ssh_net: high {
  meta:
    description                         = "possible SSH stealer"
    hash_2023_Downloads_6e35            = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi            = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $s_curl   = "curl" fullword
    $s_wget   = "wget" fullword
    $s_socket = "socket" fullword
    $h        = ".ssh" fullword
    $z_zip    = "zip" fullword
    $z_tar    = "tar" fullword
    $z_xargs  = "xargs cat"

  condition:
    filesize < 10MB and $h and any of ($s*) and any of ($z*)
}

rule curl_https_ssh: high {
  meta:
    description = "possible SSH stealer"

  strings:
    $curl   = "curl" fullword
    $ssh    = ".ssh" fullword
    $id_rsa = "id_rsa"
    $http   = "http://"
    $https  = "https://"

  condition:
    filesize < 15KB and $curl and $ssh and $id_rsa and any of ($http*)
}

rule stealssh: critical {
  meta:
    description = "SSH stealer"

  strings:
    $folder    = ".ssh" fullword
    $steal     = "stealssh"
    $stealSSH  = "stealSSH"
    $steal_ssh = "steal_ssh"

  condition:
    filesize < 10MB and $folder and any of ($steal*)
}
