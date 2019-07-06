
rule dropper {

    meta:

        sample = "42c5fd9d90b42b1e7914bf10318ba0e8d349b584b05471da78be49fc76e385a4"

        sample2 = "5e0cfae3b637a383032ec75adaf93be96af8414e9280f2e1e3382848feef2b72"

    strings:

        $a = "gDexFileName"

        $b = "lib/armeabi/libzimon.so"

        $c = "Register_PluginLoaderForCryptDexFile_Functions"

        $d = "javax/crypto/Cipher"

    condition:

        all of them

}