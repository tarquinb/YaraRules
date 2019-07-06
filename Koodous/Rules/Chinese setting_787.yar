import "androguard"


rule chinese_setting
{
	meta:
		sample = "ff53d69fd280a56920c02772ceb76ec6b0bd64b831e85a6c69e0a52d1a053fab"

	condition:
		androguard.package_name("com.anrd.sysservices") and
		androguard.certificate.issuer(/localhost/)
		
}