
rule opaque_elf_binary : critical {
  meta:
    hash_2023_Linux_Malware_Samples_060b = "060b01f15c7fab6c4f656aa1f120ebc1221a71bca3177f50083db0ed77596f0f"
    hash_2023_Linux_Malware_Samples_06ed = "06ed8158a168fa9635ed8d79679587f45cfd9825859e346361443eda0fc40b4c"
    hash_2023_Linux_Malware_Samples_0d9a = "0d9a34fd35ea6aa090c93f6f8310e111f9276bacbdf5f14e5f1f8c1dc7bf3ce5"
    hash_2023_Linux_Malware_Samples_0e49 = "0e492a3be57312e9b53ea378fa09650191ddb4aee0eed96dfc71567863b500a8"
    hash_2023_Linux_Malware_Samples_0f78 = "0f7838d0c16c24cb3b8ffc3573cc94fd05ec0e63fada3d10ac02b9c8bd95127b"
    hash_2023_Linux_Malware_Samples_1099 = "10995106e8810a432ebc487fafcb7e421100eb8ac60031e6d27c8770f6686b4e"
    hash_2023_Linux_Malware_Samples_14a3 = "14a33415e95d104cf5cf1acaff9586f78f7ec3ffb26efd0683c468edeaf98fd7"
    hash_2023_Linux_Malware_Samples_16e0 = "16e09592a9e85cd67530ec365ac2c50e48e873335c1ad0f984e3daaefc8a57b5"
	description = "Opaque ELF binary (few words)"
  strings:
    $word_with_spaces = /[a-z\-]{2,} [a-z]{2,}/
  condition:
    uint32(0) == 1179403647 and filesize < 10485760 and #word_with_spaces < 3
}
