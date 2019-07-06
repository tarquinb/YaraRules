import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "packers"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "StubApplication"
		$strings_c = "libjiagu"


	condition:
		$strings_b or $strings_c
}