rule Coinhive
{
 strings:
   $a1 = "*rcyclmnrepv*" wide ascii
   $a2 = "*coin-hive*" wide ascii
   $a3 = "*coin-hive.com*" wide ascii
   $a4 = "*com.android.good.miner*" wide ascii

 condition:
   any of them
}