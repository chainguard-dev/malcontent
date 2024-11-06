rule virtualquery: low windows {
  meta:
    description = "Retrieves virtual memory information within calling process"

  strings:
    $ref = "virtualquery" fullword

  condition:
    any of them
}

rule virtualquery_ex: medium windows {
  meta:
    description = "Retrieves virtual memory information within other processes"

  strings:
    $ref = "virtualqueryEx" fullword

  condition:
    any of them
}
