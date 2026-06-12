rule java_object_deserialization: medium java {
  meta:
    description = "deserializes Java objects from a byte stream"
    filetypes   = "class,jar,java"

  strings:
    $ois  = "java/io/ObjectInputStream"
    $read = "readObject" fullword

  condition:
    filesize < 2MB and all of them
}
