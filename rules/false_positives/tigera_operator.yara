rule tigera_operator: override {
  meta:
    description                                                     = "tigera-operator (Calico networking) Go binary"
    SIGNATURE_BASE_WEBSHELL_H4Ntu_Shell_Powered_Tsoi                = "harmless"
    SIGNATURE_BASE_H4Ntu_Shell__Powered_By_Tsoi_                    = "harmless"
    SIGNATURE_BASE_Ironshell_Php                                    = "harmless"
    SIGNATURE_BASE_Lamashell_Php                                    = "harmless"
    SIGNATURE_BASE_Safe0Ver_Shell__Safe_Mod_Bypass_By_Evilc0Der_Php = "harmless"
    SIGNATURE_BASE_Ru24_Post_Sh_Php_Php                             = "harmless"
    SIGNATURE_BASE_Simple_Cmd_Html                                  = "harmless"
    SIGNATURE_BASE_Webshell_Ru24_Post_Sh                            = "harmless"
    SIGNATURE_BASE_Webshell_Simple_Cmd                              = "harmless"

  strings:
    $tigera_module = "github.com/tigera/operator"
    $calico_api    = "github.com/tigera/api/pkg/apis/projectcalico"

  condition:
    filesize < 250MB and all of them
}
