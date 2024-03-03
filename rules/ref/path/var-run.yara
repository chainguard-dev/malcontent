rule var_run_subfolder : notable {
  meta:
    description = "References a subfolder within /var/run (rare)"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2021_miner_malxmr = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2021_CoinMiner_TB_Camelot = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"
    hash_2023_Linux_Malware_Samples_0dcf = "0dcfa54a7e8a4e631ef466670ce604a61f3b0e8b3e9cf72c943278c0f77c31a2"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2023_Linux_Malware_Samples_1822 = "1822454a2f12fae1725ef96e588e6fa2eeab58a8043e9a56ac328c14100ba937"
    hash_2023_Linux_Malware_Samples_19f7 = "19f76bf2be3ea11732f2c5c562afbd6f363b062c25fba3a143c3c6ef4712774b"
  strings:
    $var_run_folder = /\/var\/run\/[\w\.\-]{0,32}\//
	$not_var_run_run = "/var/run/run"
	$not_named = "/var/run/named"
	$not_racoon = "/var/run/racoon"
	$not_private = "/Library/PrivateFrameworks"
  condition:
	$var_run_folder and none of ($not*)
}
