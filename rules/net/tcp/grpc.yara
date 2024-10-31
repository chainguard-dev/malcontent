rule grpc {
  meta:
    description = "Uses the gRPC Remote Procedure Call framework"

  strings:
    $gRPC = "gRPC" fullword

  condition:
    any of them
}
