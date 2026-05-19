# LevarG ProGuard/R8 rules for Play Store release

# Capacitor — keep plugin classes and WebView JavaScript interfaces
-keep class com.getcapacitor.** { *; }
-keep @com.getcapacitor.annotation.CapacitorPlugin class * { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
-keepclassmembers class * extends com.getcapacitor.Plugin {
    public *;
}

# capacitor-nodejs — keep the native bridge
-keep class net.anthropic.nicknisi.capacitornodejs.** { *; }
-keep class com.nicknisi.capacitornodejs.** { *; }
-keep class hampoelz.capacitornodejs.** { *; }

# Keep Capacitor plugin annotations
-keepattributes *Annotation*

# Keep line numbers for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# AndroidX
-keep class androidx.** { *; }
-keepclassmembers class androidx.** { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}
