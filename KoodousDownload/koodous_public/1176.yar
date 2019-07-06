import "androguard"
import "file"
import "cuckoo"


rule Dropper : official
{
	meta:
		description = "This rule detects a Dropper variant"
		sample = "05f486e38f642f17fbffc5803965a3febefdcffa1a5a6eeedd81a83c835656d4"

	condition:

		androguard.service("com.lx.a.ds") and
		androguard.receiver("com.lx.a.er")

		
}