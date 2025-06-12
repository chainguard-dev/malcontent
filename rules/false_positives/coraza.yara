// https://github.com/corazawaf/coraza-coreruleset/blob/9b73b5e90a09613c7535d391a15cc9cb08c05a8d/rules/%40owasp_crs/web-shells-php.data
// https://github.com/corazawaf/coraza-coreruleset/blob/9b73b5e90a09613c7535d391a15cc9cb08c05a8d/rules/%40owasp_crs/RESPONSE-955-WEB-SHELLS.conf#L441
// Keep the overrides low so they still show up on analyze reports
rule coraza_coreruleset_override: override {
  meta:
    description                                                     = "web-shells-php.data; RESPONSE-955-WEB-SHELLS.conf"
    SIGNATURE_BASE_H4Ntu_Shell__Powered_By_Tsoi_                    = "low"
    SIGNATURE_BASE_Ironshell_Php                                    = "low"
    SIGNATURE_BASE_Lamashell_Php                                    = "low"
    SIGNATURE_BASE_Safe0Ver_Shell__Safe_Mod_Bypass_By_Evilc0Der_Php = "low"
    SIGNATURE_BASE_Webshell_Ru24_Post_Sh                            = "low"
    SIGNATURE_BASE_Webshell_Simple_Cmd                              = "low"

  strings:
    $coraza1 = "# Enable Coraza, attaching it to every transaction. Use detection"
    $coraza2 = "# Allow Coraza to access request bodies. If you don't, Coraza"
    $coraza3 = "# Coraza blocked the content. But the next, commented example contains"
    $import  = "github.com/corazawaf/coraza-coreruleset/v4"

  condition:
    all of them
}
