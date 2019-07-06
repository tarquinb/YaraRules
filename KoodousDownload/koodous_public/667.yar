import "androguard"
import "file"
import "cuckoo"


rule suidext : official
{
	meta:
		description = "detect suid"

	strings:
		$a = {50 40 2d 40 55 53 5e 2d}

	condition:
		$a
		
}