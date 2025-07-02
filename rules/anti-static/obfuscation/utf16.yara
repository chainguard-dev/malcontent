rule static_charcode_math: high {
  meta:
    description = "assembles strings from character codes and static integers"
    filetypes   = "js,ts"

  strings:
    $ref = /fromCharCode\(\d{1,16}\s{0,2}[\-\+\*\^]{1,2}\d{1,16}/

  condition:
    any of them
}
