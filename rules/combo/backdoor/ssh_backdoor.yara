rule ssh_backdoor : suspicious {
  meta:
    req = "https://www.welivesecurity.com/2013/01/24/linux-sshdoor-a-backdoored-ssh-daemon-that-steals-passwords/"
    hash_2021_trojan_SSHDoor_sshdkit = "6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
    hash_2021_trojan_SSHDoor_sshdkit_dzptg = "ee22d8b31eecf2c7dd670dde075df199be44ef4f61eb869f943ede7f5c3d61cb"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
  strings:
    $ssh_agent = "ssh_host_key"
	$ssh_authorized_keys = "authorized_keys"
    $backdoor = "backdoor"
  condition:
	$backdoor and any of ($ssh*)
}
