import "math"

rule iptables_disable : high {
  meta:
    description = "disables iptables firewall"
  strings:
	$input = "iptables -P INPUT ACCEPT"
	$output = "iptables -P OUTPUT ACCEPT"
	$forward = "iptables -P FORWARD ACCEPT"
	$flush = "iptables -F"
  condition:
	filesize < 1MB and 3 of them
}

