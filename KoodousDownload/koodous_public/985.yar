import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "androidarmor"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "cc.notify-and-report.net"
		$strings_c = "FK_G+IL7~t-6"


	condition:
		$strings_b or $strings_c
}