import "androguard"
import "file"
import "cuckoo"


rule pangxie : packer
{
  meta:
    description = "PangXie"
    example = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"

  strings:
    $lib = "libnsecure.so"

  condition:
    $lib
}