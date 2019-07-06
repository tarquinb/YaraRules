import "androguard"
import "file"
import "cuckoo"

rule allatori_demo : obfuscator
{
  meta:
    description = "Allatori demo"


  strings:
    $s = "ALLATORIxDEMO"

  condition:
    $s
}