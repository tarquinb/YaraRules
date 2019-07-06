import "androguard"
import "file"
import "cuckoo"


rule Btest
{
	meta:
		description = "btest"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_a = "aschannel" fullword
		$strings_b = "activesend" fullword
		$strings_c = "b_zq_lemon001" fullword


	

	condition:
		$strings_a or $strings_b or $strings_b or $strings_c
}