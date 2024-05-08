
rule dot_env_getter : high {
  meta:
    description = "Requests /.env URLs via HTTP"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
  strings:
    $ref = "GET /.env"
  condition:
    any of them
}
