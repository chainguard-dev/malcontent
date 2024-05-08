
rule system_fs_manipulator : notable {
  meta:
    description = "Modifies files within system directories"
  strings:
    $in_usr = /(mv|chattr|rm|touch) \/(bin|root|sbin|usr|var|lib|lib64|boot)\/[ \.\w\/]{0,64}/
    $not_mdm = "/var/db/MDM_EnableManagedApps"
  condition:
    $in_usr and none of ($not*)
}
