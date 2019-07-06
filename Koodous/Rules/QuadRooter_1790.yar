import "androguard"
import "file"
import "cuckoo"


rule QuadRooter
{
	meta:
		description = "QuadRooter"
		sample = ""

	strings:
		$a = "/dev/kgsl-3d0"

	condition:
		
		$a
}