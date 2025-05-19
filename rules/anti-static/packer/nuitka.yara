import "math"

rule nuitka: critical {
  meta:
    description = "packed with Nuitka (Python compiler)"
    filetypes   = "py"

  strings:
    $old = "onefile_%PID%_%TIME%"
    $new = "{TEMP}/onefile_{PID}_{TIME}"

  condition:
    filesize < 25MB and any of them and math.entropy(0, filesize) > 7
}
