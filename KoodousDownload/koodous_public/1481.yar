import "androguard"
import "file"
import "cuckoo"


rule Godless
{
	meta: 
		description = "This rule detects the AndroidOS.Godless Auto-Rooting Trojan"

	strings:
		$a = "KEY_REUEST_TEMP_ROOT"
		$c = "downloadUrl"

	condition:
		($a and $c)
}