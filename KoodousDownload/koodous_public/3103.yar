import "androguard"

rule leakerlocker
{
	meta:
		description = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
		sample = "486f80edfb1dea13cde87827b14491e93c189c26830b5350e31b07c787b29387"

	strings:
		$ = "updatmaster.top/click.php?cnv_id" nocase
		$ = "goupdate.bid/click.php?cnv_id" nocase
		$ = "personal data has been deleted from our servers and your privacy is secured" nocase

	condition:
		2 of them
		
}