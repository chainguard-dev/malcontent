rule busybox_runner : suspicious {
  meta:
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2023_Linux_Malware_Samples_1fce = "1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3"
    hash_2023_Linux_Malware_Samples_68c6 = "68c67c4e38c1b5a1a2897c5f6d25456e989f5a94c359137ea040e79ca4a588aa"
    hash_2023_Linux_Malware_Samples_9ae6 = "9ae6e75c6c9b98b96a411eed54ec07ce1d9e658d7e9a3ad84f03da2f53dfc9b7"
    hash_2023_Linux_Malware_Samples_b698 = "b6984474b33ca3f299ff586dae6822ed70d297803258e860c2a3a1e47abbf915"
    hash_2023_Linux_Malware_Samples_bc5c = "bc5c2358e58876be7955fa0c8f5514f4d35e5353b93ba091216b2371470da988"
    hash_2021_trojan_Mirai_Tsunami = "c8aeb927cd1b897a9c31199f33a6df9f297707bed1aa0e66d167270f1fde6ff5"
  strings:
    $b_busybox = /\/bin\/busybox \w{2,16}[ \/\w\.]{0,64}/
  condition:
    all of them
}
