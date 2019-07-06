import "androguard"
import "file"
import "cuckoo"


rule ElGato : Ransom
{
	meta:
		description = "https://blogs.mcafee.com/mcafee-labs/cat-loving-mobile-ransomware-operates-control-panel/"
		
  strings:
        $text_string = "MyDifficultPassw"
		$text_2 = "EncExc"

    condition:
       $text_string or $text_2
 }