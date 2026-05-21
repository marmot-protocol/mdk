# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in an Android Library's build.gradle file.

# Keep the JNA classes and our generated bindings
-keep class com.sun.jna.** { *; }
-keep class * extends com.sun.jna.** { *; }
-keep class build.marmot.mdk.** { *; }

# JNA's Native$AWT references java.awt.* which doesn't exist on Android.
# Without this, R8 fails consumer builds with "Missing class java.awt.Component" etc.
-dontwarn java.awt.**
