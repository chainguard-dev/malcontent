private rule package_scripts {
  strings:
    $npm_name        = /"name":/
    $npm_version     = /"version":/
    $npm_description = /"description":/
    $npm_lint        = /"lint":/
    $npm_test        = /"test":/
    $npm_postversion = /"postversion":/
    $npm_postinstall = /"postinstall":/
    $scripts         = /"scripts":/

  condition:
    filesize < 32KB and 3 of ($npm*) and $scripts
}

rule npm_fetcher: high {
  meta:
    description = "npm installer makes accesses external URLs"

  strings:
    $fetch = /"(curl|wget) /
    $url   = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/

  condition:
    package_scripts and $fetch and $url
}

rule npm_dev_tcp: critical {
  meta:
    description = "npm installer makes accesses external hosts via /dev/tcp"

  strings:
    $dev_tcp = /\/dev\/tcp\/[\w\.\/]{0,32}/

  condition:
    package_scripts and $dev_tcp
}

rule npm_ping: critical {
  meta:
    description = "npm installer makes accesses external hosts via ping"

  strings:
    $ping = /ping -\w [\w\-\. \$]{0,63}/

  condition:
    package_scripts and $ping
}

rule npm_sensitive_files: high {
  meta:
    description = "npm installer accesses system information"

  strings:
    $ = "/proc/version"
    $ = "/proc/net/fib_trie"
    $ = "/proc/net/if_inet6"
    $ = "/etc/shadow"
    $ = "/etc/hosts"
    $ = "/etc/passwd"

  condition:
    package_scripts and any of them
}

rule npm_recon_commands: high {
  meta:
    description = "npm installer reconnaissance"

  strings:
    $ = /\"uname -a/
    $ = "cat /etc/shadow"

  condition:
    package_scripts and any of them
}

rule npm_install_credential_exfiltration: high {
  meta:
    description = "npm installer references package-manager credentials and sends data over HTTP"

  strings:
    $install_pre = /"(preinstall|install|postinstall|prepare)":/

    $cred_npmrc      = ".npmrc"
    $cred_auth_token = "_authToken" fullword
    $cred_node_auth  = "NODE_AUTH_TOKEN" fullword
    $cred_npm_token  = "NPM_TOKEN" fullword
    $cred_gh_token   = "GITHUB_TOKEN" fullword

    $http_fetch   = /fetch\(\s{0,4}[\"']https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,128}/
    $http_request = /require\(\s{0,4}[\"']https{0,1}[\"']\)/
    $http_curl    = /(curl|wget) .{0,128}https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,128}/
    $http_url     = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,128}/
    $http_post    = "POST" fullword

  condition:
    package_scripts and $install_pre and any of ($cred*) and
    ($http_fetch or $http_curl or ($http_request and $http_post) or ($http_url and $http_post))
}
