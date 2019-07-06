import "androguard"
import "file"
import "cuckoo"

rule allatoristrong : obfuscator
{
  meta:
    description = "Allatori"


  strings:
    $s = "ALLATORI" nocase
	$n = "ALLATORIxDEMO"

  condition:
    $s and not $n
}