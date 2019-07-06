import "androguard"

$a = "/cellphone-tips\.com/"

rule random: adware
{
    condition:
        androguard.url(/cellphone-tips\.com/) or 
		$a
}