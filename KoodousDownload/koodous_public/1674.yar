import "androguard"


rule UrlDownloader : Downloader
{
	condition:
		androguard.url(/stat\.siza\.ru/) or 
		androguard.url(/4poki\.ru/) or 
		androguard.url(/dating\-club\.mobie\.in/) or 
		androguard.url(/systems\.keo\.su/)
}