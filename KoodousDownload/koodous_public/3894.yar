import "androguard"
import "file"
import "cuckoo"

rule xposed : anti_hooking
{
	meta:
		description = "Xposed"
		info        = "xxxxxxx"
		example     = ""

	strings:
		$a = "xposed"
		$b = "rovo89"

	condition:
		all of them
}