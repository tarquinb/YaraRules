import "androguard"
import "file"
import "cuckoo"


rule liapp : packer
{
  meta:
    description = "LIAPP"

  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"

  condition:
    any of ($dir, $lib)
}