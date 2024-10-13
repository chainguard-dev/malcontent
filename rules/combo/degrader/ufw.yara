import "math"

rule ufw_disable : high {
  meta:
    description = "disables ufw firewall"
  strings:
    $ufw = "ufw" fullword
    $disable = "disable" fullword
  condition:
    all of them and math.abs(@ufw - @disable) >= 8
}
