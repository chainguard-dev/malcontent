rule grype_offline_db: override {
  meta:
    descriptions                    = "vulnerability.db"
    SIGNATURE_BASE_Hacktool_Samples = "harmless"
    SIGNATURE_BASE_Sql_Php_Php      = "harmless"
    Windows_Trojan_Jupyter_56152e31 = "harmless"
    hacktool_chisel                 = "harmless"
    perl_reverse_shell              = "harmless"
    polkit_pkexec_exploit           = "harmless"
    systemctl_botnet_client         = "harmless"

  strings:
    $grype    = "grype"
    $f_index  = "CREATE INDEX"
    $f_sqlite = "SQLite format 3"
    $f_table  = "CREATE TABLE"

  condition:
    filesize > 2048MB and #grype > 500 and all of ($f*)
}
