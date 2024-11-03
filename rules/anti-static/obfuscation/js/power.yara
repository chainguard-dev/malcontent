rule over_powered_arrays: high {
  meta:
    description = "uses many powered array elements (>25)"
    filetypes   = "javascript"

  strings:
    $function    = /function\(\w,/
    $power_array = /\w\[\d{1,4}\]\^\w\[\d{1,4}\]/

  condition:
    filesize < 5MB and $function and #power_array > 25
}
