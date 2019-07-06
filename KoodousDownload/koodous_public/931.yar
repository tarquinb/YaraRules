import "androguard"
import "file"
  

rule wait_for_the_police : official
{
	meta:
		description = "This rule detects apps created by GYM that are SMS-frauds but looks like ramsomware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "iiAttention, you are trying to commit a crime. Please wait while a police car goes to your position. thanks"
		$b = " intentando cometer un delito, por favor, espere mientras un coche patrulla se dirige a su posici"

	condition:
		androguard.certificate.issuer(/GYM/) and 
		androguard.certificate.sha1("55C1FB97AC36FCCEC1175CF06DAA73214B23054F") and
		($a or $b)
		
}