import "androguard"


rule clicker : urls
{
	meta:
		description = "This rule detects the android clicker variat"
		sample = "b855bcb5dcec5614844e0a49da0aa1782d4614407740cb9d320961c16f9dd1e7"

	condition:
		androguard.url(/bestmobile\.mobi/) or 
		androguard.url(/oxti\.org/) or
		androguard.url(/oxti\.net/) or
		androguard.url(/oin\.systems/) or 
		androguard.url(/wallpapers535\.in/) or 
		androguard.url(/pop\.oin\.systems/)
}