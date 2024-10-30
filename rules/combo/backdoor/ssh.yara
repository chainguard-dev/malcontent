rule ssh_backdoor: high {
  meta:
    req                                                                                       = "https://www.welivesecurity.com/2013/01/24/linux-sshdoor-a-backdoored-ssh-daemon-that-steals-passwords/"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf                         = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    hash_2023_Linux_Malware_Samples_6de1                                                      = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"

  strings:
    $ssh_agent           = "ssh_host_key"
    $ssh_authorized_keys = "authorized_keys"
    $backdoor            = "backdoor"

  condition:
    $backdoor and any of ($ssh*)
}
