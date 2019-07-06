import "androguard"



rule Xavier
{
	meta:
		description = "Picks up samples with Xavier defined activity"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:

		androguard.activity(/xavier.lib.XavierActivity/i)

}