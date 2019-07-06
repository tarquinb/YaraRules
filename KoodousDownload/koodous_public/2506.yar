import "androguard"

rule Trojan_Droidjack
{
  meta:
      author = "https://twitter.com/SadFud75"
  condition:
      androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}