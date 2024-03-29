
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
    $u_upx_sig = "UPX!"
    $u_packed = "executable packer"
    $u_is_packed = "This file is packed"

	$not_upx = "UPX_DEBUG_DOCTEST_DISABLE"
  condition:
    any of ($u*) in (0..1024) and none of ($not*)
}
