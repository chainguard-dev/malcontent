rule acme_sh: override {
  meta:
    description               = "acme.sh"
    echo_decode_bash_probable = "medium"
    iplookup_website          = "medium"
    sys_net_recon_exfil       = "medium"
    cmd_dev_null_quoted       = "medium"

  strings:
    $ref = "https://github.com/acmesh-official"

  condition:
    $ref
}
