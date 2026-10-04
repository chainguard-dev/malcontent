rule vunnel_govulndb_release_dates: override {
  meta:
    description     = "vunnel/providers/govulndb/go_module_release_dates_data.py and its .pyc"
    hacktool_chisel = "harmless"

  strings:
    $release_dates = /GO_MODULE_RELEASE_DATES/
    $update_task   = /update-go-release-dates/

  condition:
    filesize < 500KB and all of them
}
