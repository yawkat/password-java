# R8 rules for the release build

# The database model is (de)serialized by Jackson through reflection: keep the classes with their constructors,
# fields and accessors (Lombok-generated), and the annotations and generic signatures Jackson reads.
-keep class at.yawk.password.model.** { *; }
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations

# Jackson 2 instantiates parts of itself reflectively (e.g. its optional JDK support in databind.ext) and reads its
# own annotations; keep databind and core whole rather than chase individual classes.
-keep class com.fasterxml.jackson.databind.** { *; }
-keep class com.fasterxml.jackson.core.** { *; }
-keep @interface com.fasterxml.jackson.annotation.** { *; }
-keep class com.fasterxml.jackson.annotation.** { *; }
# optional integrations with JDK APIs that don't exist on Android (java.beans, javax.xml, ...)
-dontwarn com.fasterxml.jackson.databind.ext.**
-dontwarn java.beans.**

# BouncyCastle is only called directly (Argon2, HKDF, Ed25519, SCrypt), so it can be shrunk. Some of its classes refer
# to JDK APIs that Android lacks (JNDI/LDAP, javax.naming); they are never used here.
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# optional compile-time annotations
-dontwarn org.jetbrains.annotations.**
-dontwarn lombok.**
