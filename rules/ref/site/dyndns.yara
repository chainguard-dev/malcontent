
rule dynamic_dns_user : notable {
  meta:
    hash_2021_miner_KB_Elvuz = "0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2023_Linux_Malware_Samples_a3a6 = "a3a6f6af9047ef527a89445c2cf297e6dd0828f1ddd6d97bf4bb9ed799a738bb"
  strings:
    $d_dyndns = "dyndns"
    $d_no_ip = "no-ip."
    $d_eu_org = "eu.org"
    $d_chickenkiller = "chickenkiller"
    $d_hopto_org = "hopto.org"
    $d_ddns_name = "ddns.name"
    $d_duckdns = "duckdns"

	$junk = "amakawababia"
  condition:
    any of ($d*) and not $junk
}
