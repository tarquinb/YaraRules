import "androguard"


rule Safe : Creativeglance
{
	
	condition:
		androguard.certificate.sha1("2f0bd554308b8193c3486aec1d3841c70b13c866")
}