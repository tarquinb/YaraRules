import "androguard"

rule Jiaguo
{
	meta:
		description = "Jiaguo"
		sample = "0a108ace8c317df221d605b2e3f426e4b3712e480f8a780f3c9c61e7bc20c520"

	strings:
		$a = "assets/libjiagu.so"
		$b = "assets/libjiagu_x86.so"

	condition:
		$a and $b
}