rule Trojan_Androrat
{
  meta:
      Author = "https://www.twitter.com/SadFud75"
  strings:
      $s_1 = "Hello World, AndroratActivity!" wide ascii
      $s_2 = "Lmy/app/client/AndroratActivity;" wide ascii
      $s_3 = "Androrat.Client.storage" wide ascii
  condition:
      any of them
}