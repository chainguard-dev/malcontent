rule timescaledb_docker_ha_post_init: override {
  meta:
    description               = "/scripts/post_init.sh"
    bash_dev_tcp_hardcoded_ip = "low"
    bash_dev_tcp              = "low"

  strings:
    $timescaledb_ext = "CREATE EXTENSION timescaledb"
    $pgbackrest_api  = "pgBackRest API"

  condition:
    filesize < 2048 and all of them
}
