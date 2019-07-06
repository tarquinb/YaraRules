import "androguard"
import "file"
import "cuckoo"


rule Dresscode : official
{
	meta:
		description = "http://blog.checkpoint.com/2016/08/31/dresscode-android-malware-discovered-on-google-play/"
		sample = "3bb858e07a1efeceb12d3224d0b192fc6060edc8f5125858ca78cdeee7b7adb9"


	condition:
		androguard.url(/inappertising\.org/) or
		cuckoo.network.dns_lookup(/inappertising\.org/) 
		
}