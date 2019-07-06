import "androguard"

rule Trojan_Inazigram {

	strings:
		$ = "osmanfurkanaydin.com.tr"
		$ = "realfollowers.net"
		$ = "freetakipci.com"
		$ = "instafenomeni.net"
		$ = "instagramaraci.com"
		$ = "iyitakip.net"
		$ = "instahobi.com"
		$ = "freetakipci.com"
		$ = "instahile.in"
		$ = "atbdigitalmedia.xyz"
		$ = "gramtakip.org"
		$ = "instamoda.org"
		$ = "instabayim.com"
		$ = "inancgultekin.com.tr"
		$ = "gncinstagram.com"
		$ = "bayihizmet.com"
		$ = "followerinsta.com"
		$ = "instagramtakipci.net"
		$ = "panelinsta.net"
		$ = "instagram.begenapp.net"
		$ = "insfollow.com"
		$ = "piscode.me"
		$ = "inslikes.com"
	
	condition:
		androguard.certificate.sha1("5DED7DE82D9A4606E553AA34B689D231144B2636") or
		1 of them and not androguard.package_name(/deebrowser/)

}