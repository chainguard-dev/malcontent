include "rules/global.yara"

import "math"

rule setuptools_random: critical {
  meta:
    description = "Python library installer that exhibits random behavior"
    filetypes   = "py"

  strings:
    $ref              = "import random"
    $not_easy_install = "pid = random.randint(0, sys.maxsize)"

  condition:
    python_setup and $ref and none of ($not*)
}

rule java_random: low {
  meta:
    description = "exhibits random behavior"
    filetypes   = "java"

  strings:
    $ref = "java/util/Random"

  condition:
    any of them
}

rule go_rand: medium {
  meta:
    description = "exhibits random behavior"
    filetypes   = "go"

  strings:
    $ref = "math/rand"

  condition:
    filesize < 100MB and any of them
}

rule rand_call: medium {
  meta:
    description = "exhibits random behavior"
    filetypes   = "c,pl,php"

  strings:
    $ref = "rand()"

  condition:
    filesize < 1MB and any of them
}

rule random: low {
  meta:
    description = "uses a random number generator"

  strings:
    $ref  = /\w{0,16}random\w{0,16}/ fullword
    $ref2 = /\w{0,16}Random\w{0,16}/ fullword

  condition:
    any of them
}
