rule webrtc_peer: medium {
  meta:
    description = "makes outgoing WebRTC connections"

  strings:
    $ref = "RTCPeerConnection"

  condition:
    any of them
}

rule webrtc_blockhain: medium {
  meta:
    description = "makes outgoing WebRTC connections, uses blockchain"

  strings:
    $ref  = "RTCPeerConnection"
    $ref2 = "blockchain"

  condition:
    all of them
}
