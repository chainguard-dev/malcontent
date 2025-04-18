rule iplookup_website: high {
  meta:
    description = "public service to discover external IP address"

  strings:
    $ipify       = /ipify\.org{0,1}/
    $wtfismyip   = "wtfismyip"
    $iplogger    = "iplogger.org"
    $getjsonip   = "getjsonip"
    $ipconfig_me = "ifconfig.me"
    $icanhazip   = "icanhazip"
    $grabify     = "grabify.link"
    $ident_me    = "ident.me" fullword
    $showip_net  = "showip.net" fullword
    $ifconfig_io = "ifconfig.io" fullword
    $ifconfig_co = "ifconfig.co" fullword
    $ipinfo      = "ipinfo.io"
    $check_ip    = "checkip.amazonaws.com"

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 250MB and any of them and none of ($not*)
}

rule v6_ipinfo_website: override {
  meta:
    iplookup_website = "medium"

  strings:
    $v6 = "v6.ipinfo.io"

  condition:
    any of them
}

rule iplookup_obfuscated: critical {
  meta:
    description = "obfuscated public service to discover external IP address"

  strings:
    $ipify_x     = "ipify.org" xor(1-255)
    $wtfismyip_x = "wtfismyip" xor(1-255)
    $iplogger_x  = "iplogger.org" xor(1-255)
    $grabify_x   = "grabify.link" xor(1-255)
    $getjsonip_x = "getjsonip" xor(1-255)
    $ipinfo_x    = "ipinfo.io" xor(1-255)
    $iplog_ugh   = /iplogger\".{0,8}org/

  condition:
    any of them

}

rule iplookup_website_base64: critical {
  meta:
    description = "public service to discover external IP address"

  strings:
    $check_ip    = "checkip.amazonaws.com" base64
    $getjsonip_b = "getjsonip" base64
    $ipify_b     = "ipify.or" base64
    $ipinfo_b    = "ipinfo.io" base64
    $iplogger_b  = "iplogger.org" base64
    $wtfismyip_b = "wtfismyip" base64

  condition:
    any of them
}

rule iplookup_website_xor: critical {
  meta:
    description = "public service to discover external IP address"

  strings:
    $ipify_x     = "ipify.org" xor(1-255)
    $wtfismyip_x = "wtfismyip" xor(1-255)
    $iplogger_x  = "iplogger.org" xor(1-255)
    $getjsonip_x = "getjsonip" xor(1-255)
    $ipinfo_x    = "ipinfo.io" xor(1-255)

  condition:
    any of them
}

rule python_list_comprehension: high {
  meta:
    description = "discover IP address via socket connection"

  strings:
    $ref = "[socket.socket(socket.AF_INET, socket.SOCK_DGRAM"

  condition:
    any of them
}
