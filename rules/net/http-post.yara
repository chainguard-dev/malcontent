rule http_post : notable {
	meta:
		pledge = "inet"
		description = "Able to submit content via HTTP POST"
	strings:
		$POST = "POST"
		$h_HTTP = "HTTP"
		$http = "http"
	condition:
		$POST and any of ($h*)
}

rule form_data_reference : notable {
  meta:
	description = "Able to submit form content via HTTP POST"
    hash_2019_trojan_NukeSped_Lazarus_AppleJeus = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
    hash_2014_trojan_Lamberts_greenlambert = "af7c395426649c57e44eac0bb6c6a109ac649763065ff5b2b23db71839bac655"
    hash_2023_trojan_JokerSpy_Python = "aa951c053baf011d08f3a60a10c1d09bbac32f332413db5b38b8737558a08dc1"
    hash_2021_CoinMiner_Sysrv = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
  strings:
    $f_content_dispo_name = "Content-Disposition: form-data; name="
    $f_multipart = "multipart/form-data; boundary="
  condition:
    any of ($f_*)
}
