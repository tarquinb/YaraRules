
rule downloader

{

    meta:

        description = "This rule detects applications that download another one"

        sample = "905db4c4fecac8a9d4b9d1cd16da97ea980aee58b88c78b0e636ff4144f24928"


    strings:

        $a = "Lcom/yr/sxmn4/ui/ai;" wide ascii

        $b = "Name: com/tencent/mm/sdk/platformtools/rep5402863540997075488.tmp"

        $c = "32102=\\u30af\\u30e9\\u30a4\\u30a2\\u30f3\\u30c8\\u306f\\u73fe\\u5728\\u5207\\u65ad\\u4e2d\\u3067\\u3059" wide ascii


    condition:

        all of them


}