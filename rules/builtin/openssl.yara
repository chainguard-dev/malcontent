rule openssl : notable {
	meta:
		description = "This binary includes OpenSSL source code"
	strings:
		$ref = "OpenSSL/"
	condition:
		any of them
}

rule elf_with_bundled_openssl : suspicious {
  meta:
    hash_2017_RiskTool_PUA_uselvj623 = "bcf92e1a88f9418739ce5b23acce1618232de1333a5143c7418271f1cb5e7626"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_miner_udtwc = "9a7e8ed9621c08964bd20eb8a95fbe9853e12ebc613c37f53774b17a2cbe9100"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2023_Linux_Malware_Samples_2f85 = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
  strings:
    $aes_part = "AES part of OpenSSL"
  condition:
    uint32(0) == 1179403647 and $aes_part
}


