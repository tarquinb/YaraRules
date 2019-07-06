import "androguard"
import "file"
import "cuckoo"


rule a : obfuscator
{

  strings:
    // Obfuscated Lpackage/class/: "L([a-z]\1{5}\/[a-z]{6}\/".
    // AFAIK, Yara does not support backreferences at the moment, thus this is the combo:
    $pkg = /L(a{6}|b{6}|c{6}|d{6}|e{6}|f{6}|g{6}|h{6}|i{6}|j{6}|k{6}|l{6}|m{6}|n{6}|o{6}|p{6}|q{6}|r{6}|s{6}|t{6}|u{6}|v{6}|w{6}|x{6}|y{6}|z{6})\/[a-z]{6}/


  condition:
    all of them
}