include "rules/global/global.yara"

rule npm_fetcher: high {
  meta:
    description = "npm installer makes accesses external URLs"

  strings:
    $fetch = /"(curl|wget) /
    $url   = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/

  condition:
    global_package_scripts and $fetch and $url
}

rule npm_dev_tcp: critical {
  meta:
    description = "npm installer makes accesses external hosts via /dev/tcp"

  strings:
    $dev_tcp = /\/dev\/tcp\/[\w\.\/]{0,32}/

  condition:
    global_package_scripts and $dev_tcp
}

rule npm_ping: critical {
  meta:
    description = "npm installer makes accesses external hosts via ping"

  strings:
    $ping = /ping -\w [\w\-\. \$]{0,63}/

  condition:
    global_package_scripts and $ping
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
    global_package_scripts and any of them
}

rule npm_recon_commands: high {
  meta:
    description = "npm installer reconnaissance"

  strings:
    $ = /\"uname -a/
    $ = "cat /etc/shadow"

  condition:
    global_package_scripts and any of them
}
