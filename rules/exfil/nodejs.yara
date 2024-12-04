import "math"

rule nodejs_sysinfoexfil: high {
  meta:
    description = "may gather and exfiltrate system information"

  strings:
    $proc1        = "process.platform"
    $proc2        = "process.arch"
    $proc3        = "process.versions"
    $request_http = /require\([\"\']https{0,1}[\"\']\)/
    $post         = "POST"

    $not_filename = "${process.arch}-${process.versions.modules}"

  condition:
    filesize < 16384 and $request_http and $post and 2 of ($proc*) and none of ($not*)
}

rule nodejs_phone_home: high {
  meta:
    description = "accesses system information and reports back"

  strings:
    $f_homedir    = "os.homedir"
    $f_userinfo   = "userInfo"
    $f_dns        = "dns.getServers"
    $f_readdir    = "readdirSync"
    $f_netinfo    = "networkInterfaces"
    $f_totalmem   = "os.totalmem"
    $f_uptime     = ".uptime"
    $f_dirname    = "__dirname"
    $f_cwd        = ".cwd()"
    $f_hostname   = ".hostname()"
    $f_resolve    = "resolve('~')"
    $serial_json  = "JSON.stringify"
    $serial_hex   = ".toString('hex')"
    $require_http = /require\([\"\']https{0,1}[\"\']\)/
    $require_dns  = /require\([\"\']dns[\"\']\)/

  condition:
    filesize < 8KB and any of ($require*) and any of ($serial*) and 3 of ($f*)
}

rule nodejs_phone_hom_obscure: critical {
  meta:
    description = "accesses system information and uploads it"

  strings:
    $f_homedir  = "homedir"
    $f_userinfo = "userInfo"
    $f_dns      = "getServers"
    $f_readdir  = "readdirSync"
    $f_netinfo  = "networkInterfaces"
    $f_totalmem = "totalmem" fullword
    $f_uptime   = "uptime" fullword
    $f_dirname  = "dirname" fullword
    $f_cwd      = "cwd" fullword
    $f_hostname = "hostname" fullword
    $f_resolve  = "resolve('~')"

    $http_hostname = "'hostname':"
    $http_post     = "POST"
    $http_content  = "Content-Type"

    $ob_return = /return _{0,4}0x[\w]{0,32}/
    $ob_const  = /const _{0,4}0x[\w]{0,32}=[\w]{0,32}/

  condition:
    filesize < 128KB and all of ($http*) and any of ($f*) and any of ($ob*)
}

rule nodejs_phone_home_interact_sh: critical {
  meta:
    description = "accesses system information and uploads it to a known site"

  strings:
    $ref     = /[\w]{8,32}\.interactsh\.com/
    $ref2    = /[\w]{8,32}\.burpcollaborator.net/
    $bc      = /[\w]{8,32}\.burpcollaborator\.net/
    $oastify = /[\w]{8,32}\.oastify\.com/
    $oastfun = /[\w]{8,32}\.oast\.fun/

  condition:
    nodejs_phone_home and any of them
}

rule nodejs_phone_home_hardcoded_host: critical {
  meta:
    description = "accesses system information and uploads it to hardcoded host"

  strings:
    $ref = /hostname: "[\w\.\-]{5,63}",/

  condition:
    nodejs_phone_home and $ref
}

rule post_hardcoded_hardcoded_host: medium {
  meta:
    description = "posts content to a hardcoded host"

  strings:
    $ref  = /hostname: "[\w\.\-]{5,63}",/
    $ref2 = /fetch\(\"https{0,1}:\/\/[\w\.\-]{5,63}.{0,64}/
    $post = "POST" fullword

  condition:
    any of ($ref*) and $post and ((math.abs(@ref - @post) <= 128) or ((math.abs(@ref2 - @post) <= 128)))
}
