rule HOME {
  meta:
    description = "Looks up the HOME directory for the current user"
    ref         = "https://man.openbsd.org/login.1#ENVIRONMENT"

  strings:
    $ref = "HOME" fullword

    $getenv = "getenv"

  condition:
    all of them
}

rule node_HOME {
  meta:
    description = "Looks up the HOME directory for the current user"
    ref         = "https://man.openbsd.org/login.1#ENVIRONMENT"
    filetypes   = "js,ts"

  strings:
    $ref = "env.HOME" fullword

  condition:
    all of them
}

rule py_HOME {
  meta:
    description = "Looks up the HOME directory for the current user"
    filetypes   = "py"

  strings:
    $ref = "os.path.expanduser(\"~\")" fullword

  condition:
    all of them
}
