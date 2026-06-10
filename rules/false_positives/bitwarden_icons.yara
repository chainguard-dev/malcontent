rule bitwarden_icons: override {
  meta:
    description                = "/usr/lib/bitwarden-icons/Icons.dll"
    exotic_tld                 = "low"
    discord_password_post_chat = "low"
    xor_terms                  = "low"

  strings:
    $namespace = "Bit.Icons.Services"
    $psl       = "publicsuffix.org/list/public_suffix_list.dat"

  condition:
    filesize < 500KB and all of them
}
