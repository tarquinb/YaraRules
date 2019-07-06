import "androguard"
import "file"
import "cuckoo"


rule cellspy : monitor
{
	meta:
		sample = "2b1b61cc6e0e291c53bce9db0e20b536d3c8371ce92cad5fc1dec4fa3f9d06c3"


	condition:
		androguard.url(/cellspy.mobi/) or
		cuckoo.network.dns_lookup(/cellspy\.mobi/)
		
}