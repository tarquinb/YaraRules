import "androguard"
import "file"
import "cuckoo"


rule Godlike
{
	meta:
		description = "This rule detects samples belonging to Godlike malware"
		sample = "61b8f90fec5a3179978844c9336890dcc429207363181596ae9ee2c7ef6ab6b6"

	strings:
		$a = "lib/armeabi/libgodlikelib.so"
		$b = "lib/armeabi-v7a/libgodlikelib.so"

	condition:
		$a or $b
				
}