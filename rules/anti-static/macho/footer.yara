include "rules/global/global.yara"

import "math"

rule high_entropy_trailer: high {
  meta:
    description = "higher-entropy machO trailer (normally NULL) - possible viral infection"
    ref         = "https://www.virusbulletin.com/virusbulletin/2013/06/multiplatform-madness"
    filetypes   = "macho"

  strings:
    $page_zero = "_PAGEZERO"

  condition:
    filesize < 10MB and global_macho and $page_zero and math.entropy(filesize - 1024, filesize - 1) >= 4
}
