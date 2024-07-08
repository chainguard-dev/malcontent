
rule nodejs_sysinfoexfil : high {
  meta:
    description = "may gather and exfiltrate system information"
    hash_2023_botbait = "1b92cb3d4b562d0eb05c3b2f998e334273ce9b491bc534d73bcd0b4952ce58d2"
    hash_2015_package_index = "ca4a74ebf4a5eb00d7d5b668b5e702161ed30160d88cfed2d249aa5523b30d86"
  strings:
    $proc1 = "process.platform"
    $proc2 = "process.arch"
    $proc3 = "process.versions"
    $request_http = /require\([\"\']https{0,1}[\"\']\)/
    $post = "POST"
  condition:
    filesize < 16384 and $request_http and $post and any of ($proc*)
}

rule nodejs_phone_home : high {
  meta:
    description = "accesses system information and reports back"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
  strings:
    $f_homedir = "os.homedir("
    $f_userinfo = "userInfo()"
    $f_dns = "dns.getServers"
    $f_readdir = ".readdirSync("
    $f_netinfo = "os.networkInterfaces("
    $f_totalmem = "os.totalmem()"
    $f_uptime = ".uptime()"
    $f_dirname = "__dirname"
    $serial_json = "JSON.stringify"
    $serial_hex = ".toString('hex')"
    $require_http = /require\([\"\']https{0,1}[\"\']\)/
    $require_dns = /require\([\"\']dns[\"\']\)/
  condition:
    filesize < 32768 and any of ($require*) and any of ($serial*) and 4 of ($f*)
}

rule nodejs_phone_home_interact_sh : critical {
  meta:
    description = "accesses system information and uploads it to a known site"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
  strings:
    $ref = /[\w]{8,32}\.interactsh\.com/
    $ref2 = /[\w]{8,32}\.burpcollaborator.net/
  condition:
    nodejs_phone_home and any of them
}

rule nodejs_phone_home_hardcoded_host : critical {
  meta:
    description = "accesses system information and uploads it to hardcoded host"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
  strings:
    $ref = /hostname: "[\w\.]{5,63}",/
  condition:
    nodejs_phone_home and $ref
}
