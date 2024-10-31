rule iokit_user {
  meta:
    description = "Ability to specify additional IOUserClient subclasses to open or to set properties on."
    doc         = "https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html"

  strings:
    $ref = "com.apple.security.temporary-exception.iokit-user-client-class" fullword

  condition:
    any of them
}
