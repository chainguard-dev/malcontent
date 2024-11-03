rule unsigned_bitwise_math: high {
  meta:
    description = "uses unsigned bitwise math"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "javascript"

  strings:
    $left  = /[a-z]\>\>\>\d{1,3}/
    $right = /[a-z]\>\>\>\d{1,3}/

  condition:
    filesize < 5MB and (#left > 25 or #right > 25)
}
