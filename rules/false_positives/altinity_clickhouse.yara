rule altinity_clickhouse_keeper_debug: override {
  meta:
    description                                          = "clickhouse-keeper.debug detached debug symbols file"
    fake_section_headers_conflicting_entry_point_address = "harmless"

  strings:
    $keeper_dispatcher = "_GLOBAL__sub_I_KeeperDispatcher.cpp"
    $keeper_resource   = "gkeeper_resource_embedded_xmlData"

  condition:
    filesize < 15728640 and all of them
}
