adb push E:\eclipse-cpp\zygote_inject\libs\armeabi-v7a\zygote_inject /data/local/tmp/zygote_inject 1>nul 2>nul
adb shell chmod 777 /data/local/tmp/zygote_inject 1>nul 2>nul
adb shell su -c '/data/local/tmp/zygote_inject'