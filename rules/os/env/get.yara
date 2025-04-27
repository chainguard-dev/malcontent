rule go_getenv: harmless {
  meta:
    description = "Retrieve environment variables"

  strings:
    $go_Getenv = "Getenv" fullword

  condition:
    any of them
}

rule getenv: low {
  meta:
    description = "Retrieve environment variables"

  strings:
    $getenv        = "getenv" fullword
    $secure_getenv = "secure_getenv" fullword
    $python_val    = "os.environ"

  condition:
    any of them
}

rule get_env_val {
  meta:
    description = "Retrieve environment variable values"

  strings:
    $node_val   = /env\.[A-Z_]{3,16}/
    $python_val = /os\.environ\[[\'\"][a-zA-Z_]{1,32}[\'\"]\]/

  condition:
    any of them
}
