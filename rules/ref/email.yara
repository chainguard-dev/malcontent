
rule email_addr {
  meta:
	description = "Contains an email address"
  strings:
    $e_re = /[\w\.\-\_]{1,32}@[\w\.\-]{1,128}\.[a-z]{2,5}/ fullword
  condition:
    any of ($e*)
}

rule exotic_email_addr : notable {
  meta:
	description = "Contains an exotic email address"
    hash_2023_Unix_Ransomware_Defray_cb40 = "cb408d45762a628872fa782109e8fcfc3a5bf456074b007de21e9331bb3c5849"
  strings:
    $e_re = /[\w\.\-]{1,32}@(protonmail|mailfence|onionmail)[\w\.\-]{1,128}/
  condition:
    any of ($e*)
}