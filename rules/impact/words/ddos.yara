
rule flooder : high {
  meta:
    description = "References an IP flooder"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Linux_Malware_Samples_0afd = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
  strings:
    $ = "flooder" fullword
    $ = "FLOODER" fullword
    $ = "Flood operation"
    $ = "Starting Flood"
    $ = "stresser" fullword
    $ = "dosia" fullword
	$ = "ICMPFLOOD" fullword
	$ = "BLACKNURSE" fullword
	$ = "HYDRASYN" fullword
	$ = "KAFFER-SLAP" fullword
  condition:
    any of them
}

rule ddos : medium {
  meta:
    description = "References DDoS"
    hash_2023_Downloads_039e = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2023_UPX_11e5 = "11e557e139b44494dd243510b398bb2ac1037055c565d25ef86f04773f9b0389"
    hash_2023_UPX_11e557e139b44494dd243510b398bb2ac1037055c565d25ef86f04773f9b0389_elf_x86_64 = "4bcb87c9cd36f49d91a795b510ac1d38ea78b538b59f88cc161cdb54390d2bce"
  strings:
    $ref = "DDoS" fullword
    $ref2 = "DD0S" fullword
  condition:
    any of them
}
