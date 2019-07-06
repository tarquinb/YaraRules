import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	

	condition:
		androguard.permission(/android.permission.WRITE_APN_SETTINGS/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		not file.md5("d367fd26b52353c2cce72af2435bd0d5") and 
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}