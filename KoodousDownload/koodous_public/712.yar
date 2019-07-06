import "androguard"

rule WapCash : official
{
	meta:
		description = "This rule detects samples fom WapCash developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"

	condition:
		androguard.certificate.sha1("804B1FED90432E8BA852D85C7FD014851C97F9CE")
		
}