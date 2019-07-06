import "androguard"



rule adw
{
	meta:
		description = "adware"
		
	strings:
		// $a = "zv.play.jsp?al_id=4802&vd_id="
		$b = "http://a1.adchitu.com/ct"
		$c = "http://a1.zhaitu.info/zt/"


	condition:
		$b and $c
}