import "androguard"

rule Marcher : AlarmAction
{
	meta:
		description = "This rule detects marcher new versions"
		sample = "c20318ac7331110e13206cdea2e7e2d1a7f3b250004c256b49a83cc1aa02d233"
		author = "DMA"

	condition:
		androguard.filter(/p\d{3}\w\.AlarmAction/)
}