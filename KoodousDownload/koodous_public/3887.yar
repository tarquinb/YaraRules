import "androguard"
import "file"
import "cuckoo"


rule ollvm_v3_4 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.4"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "cd16ad33bf203dbaa9add803a7a0740e3727e8e60c316d33206230ae5b985f25"

  strings:
    // "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"
    $clang_version = "Obfuscator-clang version 3.4 "
    $based_on      = "(based on LLVM 3.4"

  condition:
    all of them
}


rule ollvm_v3_6_1 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.6.1"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "d84b45856b5c95f7a6e96ab0461648f22ad29d1c34a8e85588dad3d89f829208"

  strings:
    // "Obfuscator-LLVM clang version 3.6.1 (tags/RELEASE_361/final) (based on Obfuscator-LLVM 3.6.1)"
    $clang_version = "Obfuscator-LLVM clang version 3.6.1 "
    $based_on      = "(based on Obfuscator-LLVM 3.6.1)"

  condition:
    all of them
}


rule ollvm_v4_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 4.0"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "aaba570388d0fe25df45480ecf894625be7affefaba24695d8c1528b974c00df"

  strings:
    // "Obfuscator-LLVM clang version 4.0.1  (based on Obfuscator-LLVM 4.0.1)"
    $clang_version = "Obfuscator-LLVM clang version 4.0.1 "
    $based_on      = "(based on Obfuscator-LLVM 4.0.1)"

  condition:
    all of them
}



rule ollvm_v6_0_strenc : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0 (string encryption)"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "f3a2e6c57def9a8b4730965dd66ca0f243689153139758c44718b8c5ef9c1d17"

  strings:
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0)"
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."
    $strenc        = /datadiv_decode[0-9]{18,20}/

  condition:
    all of them
}



rule ollvm_v6_0 : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = ""

  strings:
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0)"
    // "Obfuscator-LLVM clang version 6.0.0 (trunk) (based on Obfuscator-LLVM 6.0.0git-b9ea5776)"
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."

  condition:
    all of them and not ollvm_v6_0_strenc
}



rule ollvm : obfuscator
{
  meta:
    description = "Obfuscator-LLVM version unknown"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"

  strings:
    $ollvm1 = "Obfuscator-LLVM "
    $ollvm2 = "Obfuscator-clang "

  condition:
    ($ollvm1 or $ollvm2) and
    not ollvm_v3_4 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0 and
    not ollvm_v6_0 and
    not ollvm_v6_0_strenc
}