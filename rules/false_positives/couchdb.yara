rule couchdb_doc: override {
  meta:
    description           = "/usr/share/couchdb/share/docs/couchdb.1"
    exotic_tld            = "low"
    download_sites        = "low"
    selinux_disable_val   = "low"
    chmod_group_writeable = "low"

  strings:
    $apache_couchdb = "Apache CouchDB"
    $man_header     = "APACHECOUCHDB"

  condition:
    filesize > 500000 and filesize < 3000000 and all of them
}
