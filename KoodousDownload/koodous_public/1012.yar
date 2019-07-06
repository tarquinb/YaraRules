import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "BaiduPacker"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "com.baidu.protect.StubApplication"
		$strings_a = "com.baidu.protect.StubProvider"
		$strings_c = "com.baidu.protect.A"
		$strings_d = "baiduprotect.jar"
		$strings_d = "libbaiduprotect"

	condition:
		any of them
}