import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "360 Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "libprotectClass"
		$strings_a = "libqupc"
		$strings_c = "com.qihoo.util.StubApplication"
		$strings_d = "com.qihoo.util.DefenceReport"

	condition:
		any of them
}