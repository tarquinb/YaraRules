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
		$strings_b = "libmobisecy1"



	condition:
		$strings_b 
}