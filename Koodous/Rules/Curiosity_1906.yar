import "androguard"


rule curiosity
{
	meta:
		description = "Rule to detect the curiosity malware."
		sample = "6bbaf87fe4e591399897655356911c113678c6e19d98b8b0bd01a4f5e362419e"

	strings:
		$a = "if u want to download spy application please click on :  http://185.38.248.94/api/Service/DownloadEn"
		$b = "Hello I found your private photos here  http://bit.ly/2abgToi  click to see"
		$c = /s ici http:\/\/bit\.ly\/2a9JWWk clique pour les voir/

	condition:
		androguard.url(/185\.38\.248\.94\/messages/) and androguard.permission(/vdsoft.spying.sjin.permission.C2D_MESSAGE/) or $b or $a or $c
	
}