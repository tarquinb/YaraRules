import "cuckoo"

rule smsfraud
{
	meta:
		description = "This rule detects several sms fraud applications"
		sample = "ab356f0672f370b5e95383bed5a6396d87849d0396559db458a757fbdb1fe495"
		
    condition:
		cuckoo.network.dns_lookup(/waply\.ru/) or cuckoo.network.dns_lookup(/depositmobi\.com/)

}