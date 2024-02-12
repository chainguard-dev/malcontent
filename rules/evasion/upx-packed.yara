
rule upx : suspicious {
  meta:
	description = "Binary is packed with UPX"
    hash_2022_covid_osx_agent = "7831806172857a563d7b4789acddc98fc11763aaf3cedf937630b4a9dce31419"
    hash_2018_coldroot = "d7cd18d3e6929dd1e5c12613f9a937fd45f75aa6e0ecee70908d2638f6b3ce7c"
    hash_2020_ipstorm_alien = "4cd7c5ee322e55b1c1ae49f152629bfbdc2f395e9d8c57ce65dbb5d901f61ac1"
    hash_2023_trojan_Mirai_sora_x86 = "5f73f54865a1be276d39f5426f497c21e44a309e165e5e2d02f5201e8c1f05e0"
    hash_2023_trojan_Mirai_maCarm = "b6f51ce14ba12fd254da8fa40e7fef20b76e9df57660b66121e5f16718797320"
    hash_2023_Linux_Malware_Samples_06ed = "06ed8158a168fa9635ed8d79679587f45cfd9825859e346361443eda0fc40b4c"
    hash_2023_Linux_Malware_Samples_0a4b = "0a4b417193f63a3cce4550e363548384eb007f89e89eb831cf1b7f5ddf230a51"
    hash_2023_Linux_Malware_Samples_0b9d = "0b9d850ad22de9ed4951984456e77789793017e9df41271c58f45f411ef0c3d2"
  strings:
    $upx_sig = "UPX!"
    $packed = "executable packer"
    $is_packed = "This file is packed"
  condition:
    any of them in (0..1024)
}

rule tampered_upx : suspicious {
  meta:
	description = "Binary is packed with UPX and further tampered with"
    hash_2021_trojan_Mirai_genericrxmj = "c187548577d9c3afc2d2d8dcb4c92279994bc6151472a7a076a596286ad8e404"
    hash_2021_trojan_Mirai_lrzjy = "1a796f26d5d9cc76978ecaa0ef63e603a47722545fa1e6939bd85144edcebe86"
    hash_2020_trojan_FDNCQLX_uxgkp = "ecec4df631dcebc59cc96bd1ac22657d58be0ecb7d58a74971cf90de3b4daed3"
    hash_2023_Linux_Malware_Samples_2010 = "201083e4e4e6fc5c91a21e7c84151978ceb2cd40c74d7f08afe497c699cdf1b4"
    hash_2023_Linux_Malware_Samples_4a19 = "4a192a222de58048d9fdfe160d2cec8723b50785903f9e2e9aee122fccf15e10"
    hash_2023_Linux_Malware_Samples_5304 = "53046ec20ff41109e92ae74a5d9ea300d01c07d08fff936f2c7f527cae6384ec"
    hash_2023_Linux_Malware_Samples_7935 = "793599165003c5f0cb774236db8c99554286b73d3b804b79f1f7b9864481f9fa"
    hash_2023_Linux_Malware_Samples_bb04 = "bb04b1c4160c9e614178dae9d97077791a7db01fd785bdb5640939628b09fd6b"
  strings:
    $upx_sig = "UPX!"
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
  condition:
    filesize < 1048576 and $prot_exec and not $upx_sig
}
