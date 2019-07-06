rule otherpacker
{
  meta:
    description = "AppGuard"
    // http://appguard.nprotect.com/en/index.html

  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"

  condition:
   ($stub and $encrypted_dex)
}

rule dxshield : otherpacker
{
  meta:
    description = "DxShield"
    // http://www.nshc.net/wp/portfolio-item/dxshield_eng/

  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"

  condition:
     ($decryptlib and $res)
}

rule secneo : otherpacker
{
  meta:
    description = "SecNeo"
    // http://www.secneo.com

  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"

  condition:
     any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}

rule dexprotector : otherpacker
{
 /**
 * DexProtector v6.x.x :- Demo,Standard,Business Edition (https://dexprotector.com)
 **/
  meta:
    author = "Jasi2169"
    description = "DexProtector"

  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"

  condition:
     any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}

rule kiro : otherpacker
{
  meta:
    description = "Kiro"

  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"

  condition:
     $kiro_lib and $sbox
}

rule jiagu : otherpacker
{
  meta:
    description = "Jiagu"
    //developed by Qihoo 360 http://jiagu.360.cn/

  strings:
    // These contain a trick function "youAreFooled"
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"

  condition:
     ($main_lib or $art_lib)
}

rule qdbh_packer : otherpacker
{
  meta:
    description = "'qdbh' (?)"

  strings:
    $qdbh = "assets/qdbh"

  condition:
     $qdbh
}

rule unknown_packer_lib : otherpacker
{
  meta:
    description = "'jpj' packer (?)"

  strings:
    $pre_jar = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 }
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F }
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 }

  condition:
    //
    ($pre_jar and $jar_data and $post_jar)
}

rule unicom_loader : otherpacker
{
  meta:
    description = "Unicom SDK Loader"

  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"

  condition:
     ($unicom_lib and ($decrypt_lib or $classes_jar))
}


rule app_fortify : otherpacker
{
  meta:
    description = "App Fortify"

  strings:
    $lib = "libNSaferOnly.so"

  condition:
     $lib
}

rule nqshield : otherpacker
{
  meta:
    description = "NQ Shield"

  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"

  condition:
     any of ($lib, $lib_sec1, $lib_sec2)
}



rule medusah : otherpacker
{
  meta:
    // https://medusah.com/
    description = "Medusah"

  strings:
    $lib = "libmd.so"

  condition:
    $lib
}

rule medusah_appsolid : otherpacker
{
  meta:
    // https://appsolid.co/
    // Samples and discussion: https://github.com/rednaga/APKiD/issues/19
    description = "Medusah (AppSolid)"

  strings:
    $encrypted_dex = "assets/high_resolution.png"

  condition:
     $encrypted_dex and not medusah
}


rule kony : otherpacker
{
  meta:
    description = "Kony"
	// http://www.kony.com/

  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"

  condition:
    $lib and $decrypt_keys and $encrypted_js
}

rule approov : otherpacker
{
  meta:
    description = "Aproov"
	// https://www.approov.io/

  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"

  condition:
     $lib and $sdk_config
}