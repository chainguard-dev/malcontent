rule eval_image_data {
  meta:
    description = "Extracts content from an inline image/png"

  strings:
    $eval = "<img src=\"data:image/png;(.*)\""

  condition:
    any of them
}
