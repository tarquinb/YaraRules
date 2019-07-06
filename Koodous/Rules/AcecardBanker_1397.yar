import "androguard"
import "file"
import "cuckoo"


rule Banker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "26d704d3a84a1186ef9c94ccc6d9fbaf, efe11f32c6b02370c7a98565cadde668"

	strings:
		$a = "http://xxxmobiletubez.com/video.php"
		$b = "http://adultix.ru/index.php"
		$c = "http://adultix.ru/forms/index.php"
	condition:
		all of them

}