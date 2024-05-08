import "math"

rule user_agent_ifconfig : suspicious {
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

rule user_agent_proc_net_route : suspicious {
  meta:
    description = "Has a user agent and collects network info"
    hash_2023_Unix_Dropper_Mirai_1703 = "1703bd27e0ae38a53e897b82554f95eaa5a88f2b0a6c2c9d973d7e34d05b2539"
    hash_2023_Unix_Dropper_Mirai_818d = "818d45523d194e31eedc81fe8a86d6f7c3af0376806078b904f10024e4d02120"
    hash_2023_Unix_Dropper_Mirai_8f9d = "8f9d9e08af48d596a32d8a7da5d045c8b1d3ffd8ccffcf85db7ecb9043c0d4be"
  strings:
    $ua = "User-Agent"
    $ua_moz = "Mozilla/"
    $ua_msie = "compatible; MSIE"
    $net_route = "/proc/net/route"
  condition:
    any of ($ua*) and any of ($net*)
}
