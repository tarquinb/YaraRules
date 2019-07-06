import "androguard"

rule Fake_Flash_Player
{
  meta:
       description = "Detects fake flashplayer apps"
	   	   
	strings:
		$string_1 = "lock"
		$string_2 = "pay"
   condition:
	 $string_1 and $string_2 and
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) 
}