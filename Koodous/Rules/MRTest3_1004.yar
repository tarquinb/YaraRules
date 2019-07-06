import "androguard"
import "file"

rule testing
{
	meta:
		description = "This rule is a test"
		
	strings:
	  $b1 = "1xRTT"
	  $b2 = "CDMA"
	  $b3 = "EDGE"
	  $b4 = "eHRPD"
	  $b5 = "EDVO revision 0"
	  $b6 = "EDVO revision A"
	  $b7 = "EDVO revision B"
	  $b8 = "GPRS"
	  $b9 = "HSDPA"
	  $b11 = "HSPA"
	  $b12 = "HSPA+"
	  $b13 = "HSUPA"
	  $b14 = "iDen"
	  $b15 = "LTE"
	  $b16 = "UMTS"
	  $b17 = "CDMA"
	  $b18 = "GSM"
	  $b19 = "SIP"
	condition:
		all of them

		
}