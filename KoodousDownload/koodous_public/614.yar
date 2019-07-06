import "cuckoo"

rule gaga01:SMSSender
{
	condition:
		cuckoo.network.dns_lookup(/gaga01\.net/)
}