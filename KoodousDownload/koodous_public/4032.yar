import "androguard"
import "file"
import "cuckoo"

rule dark_caracal
{
	meta:
		description = "This rule detects samples mentioned in the blog https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf"
		sample = "4b1918576e4be67de835a85d986b75ef"

					
	condition:
		androguard.service(/com.receive.MySe/) 
}