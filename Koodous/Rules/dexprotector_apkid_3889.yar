import "androguard"
import "file"
import "cuckoo"


rule dexprotector : obfuscator
{
  meta:
    description = "DexProtector"

  strings:
    $method = {
      07 00 02 00 00 00 02 00 00 00 00 00 3E 00 00 00
      12 01 13 00 0E 00 48 00 05 00 E0 00 00 10 01 12
      39 02 2A 00 12 32 D5 63 FF 00 48 03 05 03 D5 33
      FF 00 E1 04 06 08 D5 44 FF 00 48 04 05 04 D5 44
      FF 00 E0 04 04 08 B6 43 E1 04 06 10 D5 44 FF 00
      48 04 05 04 D5 44 FF 00 E0 04 04 10 B6 43 E1 04
      06 18 D5 44 FF 00 48 00 05 04 E0 00 00 18 B6 30
      0F 00 0D 02 39 01 FE FF 12 21 DD 02 06 7F 48 00
      05 02 E1 00 00 08 28 F5 0D 03 28 CB 0D 00 00 00
      20 00 ?? 00 37 00 00 00 02 00 ?? 00 02 01
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"

  condition:
    $method and
    all of ($a, $b, $c)
}