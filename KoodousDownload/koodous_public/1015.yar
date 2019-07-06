import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Bangcle Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "assets/bangcleplugin"
		$strings_a = "neo.proxy.DistributeReceiver"

	condition:
		any of them
}