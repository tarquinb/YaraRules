import "androguard"



rule clicker : url
{
	meta:
		description = "This rule detects the clicker variant malwares by using visited URLs"
		sample = "aa19c5038d74cf537de35b39bfbf82a35e03e4ab0635a14fdf857aabbe134382"

	condition:
		androguard.url(/^https?:\/\/.*\/z\/z2\/?/) or 
		androguard.url(/^https?:\/\/.*\/z\/z5\/?/) or
		androguard.url(/^https?:\/\/.*\/g\/getasite\/?/) or
		androguard.url(/^https?:\/\/.*\/z\/orap\/?/) or
		androguard.url(/^https?:\/\/.*\/g\/gstie\/?/)
	
}