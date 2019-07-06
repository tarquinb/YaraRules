import "androguard"
import "file"
import "cuckoo"


rule approov : packer
{
  meta:
    description = "Aproov"
	  url = "https://www.approov.io/"

  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"

  condition:
    $lib and $sdk_config
}