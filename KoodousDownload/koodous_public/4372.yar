import "androguard"
import "file"
import "cuckoo"

rule allatori : obfuscator
{
  meta:
    description = "Allatori (likely)"


  strings:
    $s = "ALLATORI" nocase
	$demo = "ALLATORIxDEMO"

  condition:
    $s and not $demo
}