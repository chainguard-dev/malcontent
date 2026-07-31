rule systemd_no_comments_or_documentation: medium {
  meta:
    ref         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    description = "systemd unit is undocumented"
    filetypes   = "service"

  strings:
    $execstart          = "ExecStart="
    $ex_comment         = "# "
    $ex_documentation   = "Documentation="
    $ex_requires_socket = /Requires=.{0,64}socket/
    $ex_condition_path  = "Condition"
    $ex_after           = "After="
    $ex_systemd         = "ExecStart=systemd-"
    $ex_output          = "StandardOutput="

  // $execstart matches inside $ex_systemd, so a unit that launches one systemd- helper
  // used to be exempt no matter what else it launched. Discount $ex_systemd by
  // occurrence count; the rest of the set is unit structure that is documentation
  // enough on its own, so those stay presence checks.

  condition:
    filesize < 4KB and $execstart and #execstart > #ex_systemd and none of ($ex_comment, $ex_documentation, $ex_requires_socket, $ex_condition_path, $ex_after, $ex_output)
}
