import "androguard"

rule detection
{
    
	strings:
		$ = "mspace.com.vn"
		$ = "optimuscorp.pw"
		$ = "ads_manager/get_facebook_ads_manager.php" 

	
	condition:
		2 of them or
		androguard.url("mspace.com.vn") or
		androguard.url("optimuscorp.pw") or
		androguard.certificate.sha1("A7E0323BFEFED2929F62EFC015ED465409479F6F") or
		androguard.certificate.issuer(/assdf/)
}