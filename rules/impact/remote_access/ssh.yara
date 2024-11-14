rule ssh_backdoor: high {
  meta:
    req = "https://www.welivesecurity.com/2013/01/24/linux-sshdoor-a-backdoored-ssh-daemon-that-steals-passwords/"

    hash_2023_Linux_Malware_Samples_6de1 = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"

  strings:
    $ssh_agent           = "ssh_host_key"
    $ssh_authorized_keys = "authorized_keys"
    $backdoor            = "backdoor"

  condition:
    $backdoor and any of ($ssh*)
}

rule sshd_backdoor_private_key: critical {
  meta:
    ref         = "https://web-assets.esetstatic.com/wls/2021/10/eset_fontonlake.pdf"
    description = "sshd contains hardcoded private key"

  strings:
    $begin = "-----BEGIN RSA PRIVATE KEY-----"
    $key   = /MIIE[\w\+]{0,64}/
    $sshd  = "usage: sshd"

  condition:
    filesize < 5MB and all of them
}

