import "androguard"
import "file"
import "cuckoo"


rule MapinDropper
{
	meta:
		description = "This rule detects mapin dropper files"
		sample = "745e9a47febb444c42fb0561c3cea794"

	strings:
		$a = "assets/systemdataPK"
		$b = "assets/systemdata"
		$e = "assets/resourcea"
		$f = "assets/resourceaPK"

	condition:
		$a or $b or $e or $f
}