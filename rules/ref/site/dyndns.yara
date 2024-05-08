
rule dynamic_dns_user : notable {
  meta:
    hash_2023_Linux_Malware_Samples_0b1c = "0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6"
    hash_2023_Linux_Malware_Samples_24ee = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2023_Linux_Malware_Samples_9f05 = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
  strings:
    $d_dyndns = "dyndns"
    $d_no_ip = "no-ip."
    $d_eu_org = "eu.org"
    $d_chickenkiller = "chickenkiller"
    $d_hopto_org = "hopto.org"
    $d_ddns_name = "ddns.name"
    $d_duckdns = "duckdns"
    $d_dont = "donttargetme"
    $junk = "amakawababia"
  condition:
    any of ($d*) and not $junk
}
