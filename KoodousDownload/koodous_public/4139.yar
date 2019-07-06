import "androguard"
import "file"
import "cuckoo"


rule app_fortify : packer
{
  meta:
    description = "App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
    $lib
}