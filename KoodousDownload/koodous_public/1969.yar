import "androguard"

rule Service:Gogle
{
	condition:
		androguard.service("com.module.yqural.gogle")
}