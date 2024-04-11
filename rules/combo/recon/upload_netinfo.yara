import "math"

rule user_agent_ifconfig: suspicious {
	meta:
		description = "Has a user agent and collects network info"
	strings:
		$ua = "User-Agent"
		$ua_moz = "Mozilla/"
		$ua_msie = "compatible; MSIE"

		$net_ifconfig = "ifconfig"
		$net_ifconfig_a = "-a"
	condition:
		any of ($ua*) and math.abs(@net_ifconfig - @net_ifconfig_a) <= 8
}


rule user_agent_proc_net_route: suspicious {
	meta:
		description = "Has a user agent and collects network info"
	strings:
		$ua = "User-Agent"
		$ua_moz = "Mozilla/"
		$ua_msie = "compatible; MSIE"

		$net_route = "/proc/net/route"
	condition:
		any of ($ua*) and any of ($net*)
}
