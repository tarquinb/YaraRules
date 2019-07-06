import "androguard"
import "file"
import "cuckoo"


rule downloader:trojan
{
	meta:
		sample = "800080b7710870e1a9af02b98ea2073827f96d3fde8ef9d0e0422f74fe7b220f"

	strings:
		$a = "Network is slow, click OK to install network acceleration tool."
		$b = "Your network is too slow"
		$c = "Awesome body. Lean and sexy."

	condition:
		all of them
}