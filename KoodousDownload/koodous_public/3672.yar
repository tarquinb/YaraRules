import "androguard"
import "file"
import "cuckoo"


rule ZNIU : official
{
	meta:
		description = "https://blog.trendmicro.com/trendlabs-security-intelligence/zniu-first-android-malware-exploit-dirty-cow-vulnerability"
		sample = "382632d30144db2ba4e8933c900ee503267d60dea5cd460d7de3df746574f2f9 "



	condition:
		androguard.package_name("com.tj.tjcty.*") and

		androguard.url(/139.129.132.111/) and
		not file.md5("b4ee8f24a748ac33d83451b874699e4d ")
}