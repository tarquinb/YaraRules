import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "Tencent Packer"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "com.tencent.StubShell.ProxyShell"
		$strings_a = "com.tencent.StubShell.ShellHelper"

	condition:
		any of them
}