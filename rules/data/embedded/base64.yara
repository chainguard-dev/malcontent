rule base64_content: medium {
  meta:
    description = "Contains embedded base64 content"

  strings:
    $b64_st = /[\"\'][\w\/\+]{24,2048}==[\"\']/

  condition:
    any of them
}

rule base64_content_reversed: high {
  meta:
    description = "Contains reversed base64 content"

  strings:
    $b64_st = /[\"\']==[\w\/\+\"\']{64,2048}/

  condition:
    any of them
}

