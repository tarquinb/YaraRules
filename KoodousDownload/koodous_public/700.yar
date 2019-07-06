import "androguard"

rule Locker : official
{
	meta:
		description = "This rule detects one variant of Locker malware"
		sample = "039668437547FE920F15C972AE8EB94F063C75409FB78D8D8C8930BD3B07DFFC"

	strings:
		$a = {64 65 6C 65 74 65 41 50 50}
		$b = {6C 6C 5F 63 6F 64 65 69 6E 70 75 74}
		$c = {6C 6C 5F 73 75 63 63 73 65 73 73}
		$d = {44 45 56 49 43 45 5F 41 44 4D 49 4E}

	condition:

		$a and $b and $c and $d

		
}