rule trojan_ref : suspicious {
  meta:
	description = "References a Trojan"
  strings:
    $s_trojan = "trojan" fullword
    $s_Trojan = "Trojan"
    $s_tr0jan = "tr0jan" fullword
  condition:
    any of ($s*)
}