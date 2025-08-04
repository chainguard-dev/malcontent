rule kong_wait: override {
  meta:
    description = "wait-for-postgres-script.yaml"
    bash_tcp    = "medium"

  strings:
    $bash = "bash -c \"9<>/dev/tcp/${KONG_PG_HOST}/${KONG_PG_PORT}\""

  condition:
    $bash
}
