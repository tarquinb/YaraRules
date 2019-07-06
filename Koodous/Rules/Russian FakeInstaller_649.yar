import "androguard"


rule russian : fakeInst
{

	condition:
		
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
		
}