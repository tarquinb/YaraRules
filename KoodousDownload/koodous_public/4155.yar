import "androguard"
import "file"
import "cuckoo"


rule appguard : packer
{
  meta:
    description = "AppGuard"
    url = "http://appguard.nprotect.com/en/index.html"

  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"

  condition:
    ($stub and $encrypted_dex)
}