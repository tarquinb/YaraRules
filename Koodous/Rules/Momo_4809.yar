import "androguard"

rule Momo
{
	condition:
		androguard.package_name("com.mobo.gram") and
		androguard.activity(/StepTwoActivityForce/i)
}