import "androguard"

//SMSSender
rule londatiga
{
	condition:
		androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}