import "androguard"
import "file"
import "cuckoo"


rule ApkPackerApplication_2
{
	meta:
		description = "ApkPackerApplication samples"

	strings:
		$string_1 = "Lapkpacker/ApkPackerApplication"
		$string_2 = "IntegrityCheck"
		
	condition:
		all of ($string_*)
		
}