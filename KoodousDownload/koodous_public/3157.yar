rule NqShield
{
	meta:
		description = "NqShield"
		
    strings:
		$nqshield_1 = "NqShield"
		$nqshield_2 = "libnqshieldx86"
		$nqshield_3 = "LIB_NQ_SHIELD"

	condition:
        any of them 
}