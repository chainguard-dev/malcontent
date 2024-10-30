rule clamav_searchindex_json: override {
  meta:
    description         = "searchindex.json"
    linux_rootkit_terms = "medium"

  strings:
    $clamav      = "clamav"
    $description = "ClamAV is an open source (GPLv2) anti-virus toolkit, designed especially for e-mail scanning on mail gateways."
    $tip         = "Tip : ClamAV is not a traditional anti-virus or endpoint security suite."

  condition:
    filesize < 5MB and all of them
}
