import "androguard"
import "file"
import "cuckoo"


rule DroidRt 
{
	meta:
		sample = "f50dc3592737532bc12ef4954cb2d7aeb725f6c5eace363c8ab8535707b614b3"

	condition:
		cuckoo.network.dns_lookup(/download\.moborobo\.com/)
}