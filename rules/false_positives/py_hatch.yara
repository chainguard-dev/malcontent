rule migrate_py: override {
  meta:
    description     = "migrate.py"
    setuptools_eval = "medium"

  strings:
    $env     = "'_HATCHLING_PORT_ADD_'"
    $literal = "literal_eval(value)"

  condition:
    filesize < 20KB and all of them
}
