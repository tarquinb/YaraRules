import "androguard"
import "file"
import "cuckoo"


rule SeSeAOV : SexApp
{
	meta:
		sample = "f93222a685f45487732e1692d6c1cbeb3748997c28ca5d61c587b21259791599"

	condition:
		cuckoo.network.dns_lookup(/h.\.tt-hongkong.com/)
		
}