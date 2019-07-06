import "androguard"
import "file"
import "cuckoo"

rule arxan : obfuscator
{
  meta:
    description = "Arxan"
    url         = "https://www.arxan.com/products/application-protection-mobile/"
    example     = "7bd1139b5f860d48e0c35a3f117f980564f45c177a6ef480588b5b5c8165f47e"

  strings:
    $pkg = /L(a{6}|b{6}|c{6}|d{6}|e{6}|f{6}|g{6}|h{6}|i{6}|j{6}|k{6}|l{6}|m{6}|n{6}|o{6}|p{6}|q{6}|r{6}|s{6}|t{6}|u{6}|v{6}|w{6}|x{6}|y{6}|z{6})\/[a-z]{6}/


    $m1 = { 10 62 (6? | 75) [14] 00 }
    $m2 = { (0b | 0d) 62 d0 [15] 00 }
    $m3 = { (0e | 10) 62 30 34 3? [15] 00 }
    $m4 = { (0b | 0d) 62 30 34 3? [13] 00 }
   

  condition:
    $pkg and
    1 of ($m*)
}