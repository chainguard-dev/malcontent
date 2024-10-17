import "math"

rule ufw_disable : high {
  meta:
    description = "disables ufw firewall"
  strings:
    $ufw = "ufw" fullword
    $disable = "disable" fullword
  condition:
    filesize < 256KB and all of them and math.abs(@ufw - @disable) >= 8
}

rule ufw_disable_word : high {
  meta:
    description = "disables ufw firewall"
  strings:
	$ref = "ufw disable" fullword
  condition:
	filesize < 256KB and $ref
}
