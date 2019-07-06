import "androguard"
import "file"
import "droidbox"


rule SmsZombie_Strings
{      
	  meta:
		description = "Yara rules for SmsZombie Applications"
		
		
	  strings:
		
		$a = "data/data/android.phone.com/files/phone.xml"
		$b_1 = "res/drawable-v1/a5.jpgPK"
        $b_2 = "res/drawable-v1/a2.jpgPK"
        $b_3 = "res/drawable-v1/a1.jpgPK"
        $b_4 = "res/drawable-v1/a6.jpgPK"
        $b_5 = "res/drawable-v1/a4.jpgPK"
        $b_6 = "res/drawable-v1/a3.jpgPK"
        $b_7 = "res/drawable-v1/a4.jpg"
        $b_8 = "res/drawable-v1/a1.jpg"
        $b_9 = "res/drawable-v1/a3.jpg"
        $b_10 = "res/drawable-v1/a2.jpg"
        $b_11 = "res/drawable-v1/a6.jpg"
        $b_12 = "res/drawable-v1/a5.jpg"
		
		condition:
		$a or all of ($b_*)and
		droidbox.sendsms(/./) 
		
		
}