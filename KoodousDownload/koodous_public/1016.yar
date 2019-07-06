import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Ijiami Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "rmeabi/libexecmain.so"
		$strings_a = "neo.proxy.DistributeReceiver"

	condition:
		any of them
}