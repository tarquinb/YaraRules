import "androguard"

rule desert_scorpion {

	strings:
		$ = /dardash.info/
		$ = /dachfunny.club/
		$ = /dardash.fun/
	
	condition:

		1 of them or androguard.certificate.sha1("194EAAE2D2C201A8A810F9B2102D82CF5110E277")

}