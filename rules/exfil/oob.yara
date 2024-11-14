rule interact_sh: high {
  meta:
    description = "uses interactsh for OOB interaction gathering"

  strings:
    $ref = /[\w]{8,32}\.interactsh\.com/

  condition:
    $ref
}

rule burp_collab: high {
  meta:
    description = "uploads content to security collaboration site"

  strings:
    $bc        = /[\w]{8,32}\.burpcollaborator\.net/
    $oastify   = /[\w]{8,32}\.oastify\.com/
    $oastfun   = /[\w]{8,32}\.oast\.fun/
    $pipedream = /[\w]{8,32}\.m\.pipedream\.net/

  condition:
    any of them
}

rule burp_collab_preinstall: critical {
  meta:
    description = "uploads content to security collaboration site from preinstall"

  strings:
    $preinstall = /\s{2,8}"preinstall": ".{12,256}/

  condition:
    filesize < 2KB and $preinstall and burp_collab
}

rule burp_collab_crypto: critical {
  meta:
    description = "uploads encrypted content to security collaboration site"

  strings:
    $crypto = /require\(['"]crypto['"]\);/

  condition:
    filesize < 24KB and $crypto and burp_collab
}
