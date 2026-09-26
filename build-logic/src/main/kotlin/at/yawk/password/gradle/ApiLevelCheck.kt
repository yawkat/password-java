package at.yawk.password.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.api.variant.CanMinifyCode
import java.io.File
import java.util.zip.ZipFile
import javax.xml.parsers.SAXParserFactory
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.kotlin.dsl.create
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register
import org.xml.sax.Attributes
import org.xml.sax.helpers.DefaultHandler

/**
 * Settings of the API level check, see [ApiLevelCheckPlugin].
 */
abstract class ApiLevelCheckExtension {
    /**
     * References that are known to be unreachable (or safe) on older Android versions, as
     * `owner/Class.method(descriptor)` to the reason. A trailing `*` matches any reference starting with the rest.
     */
    abstract val allowed: MapProperty<String, String>
}

/**
 * Fails `check` if an APK of the application refers to a platform method (`java.*`, `javax.*`, `android.*`) that does
 * not exist at the app's minSdk, according to the SDK's `api-versions.xml`.
 *
 * Lint's NewApi check only covers our own sources. This covers the libraries as well, as dexed into the APK: a Java
 * library built for a newer JDK may call methods that Android lacks and D8 doesn't backport, which then fail with
 * `NoSuchMethodError` at runtime on older devices only.
 *
 * Calls from `androidx` are not checked: those libraries are built for Android and guard newer APIs with SDK_INT
 * checks (which this check cannot see). In minified builds, class names are mapped back through R8's mapping file.
 */
class ApiLevelCheckPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create<ApiLevelCheckExtension>("apiLevelCheck")
        val components = project.extensions.getByType<ApplicationAndroidComponentsExtension>()
        components.onVariants { variant ->
            val name = variant.name.replaceFirstChar { it.uppercase() }
            val task = project.tasks.register<ApiLevelCheckTask>("check${name}ApiLevels") {
                description = "Checks that the ${variant.name} APK only calls platform methods available at minSdk"
                group = "verification"
                apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
                if ((variant as? CanMinifyCode)?.isMinifyEnabled == true) {
                    mappingFile.set(variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE))
                }
                minSdk.set(variant.minSdk.apiLevel)
                allowed.set(extension.allowed)
                apiVersions.set(project.layout.file(components.sdkComponents.bootClasspath.map { classpath ->
                    classpath.first { it.asFile.name == "android.jar" }.asFile.resolveSibling("data/api-versions.xml")
                }))
                dexdump.set(project.layout.file(project.provider {
                    val android = project.extensions.getByType<com.android.build.api.dsl.ApplicationExtension>()
                    components.sdkComponents.sdkDirectory.get().asFile
                        .resolve("build-tools/${android.buildToolsVersion}/dexdump")
                }))
                report.set(project.layout.buildDirectory.file("reports/api-levels/${variant.name}.txt"))
            }
            project.tasks.named("check") { dependsOn(task) }
        }
    }
}

@CacheableTask
abstract class ApiLevelCheckTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mappingFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apiVersions: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val dexdump: RegularFileProperty

    @get:Input
    abstract val minSdk: Property<Int>

    @get:Input
    abstract val allowed: MapProperty<String, String>

    @get:OutputFile
    abstract val report: RegularFileProperty

    private class ApiClass(val since: Int, val methods: Map<String, Int>, val supers: List<String>)

    @TaskAction
    fun check() {
        val api = parseApiVersions(apiVersions.get().asFile)
        val deobfuscate = mappingFile.orNull?.asFile?.let(::parseMapping) ?: emptyMap()
        val min = minSdk.get()
        val allowed = allowed.get()

        // referenced method -> (API level, callers)
        val violations = sortedMapOf<String, Pair<Int, MutableSet<String>>>()
        val allowedSeen = mutableSetOf<String>()
        val invoke = Regex("""invoke-\S+ \{[^}]*}, L((?:java|javax|android)/[^;]+);\.([^:]+):(\S+)""")
        val classDescriptor = Regex("""\s+Class descriptor\s+: 'L([^;]+);'""")

        fun since(owner: String, method: String, seen: MutableSet<String> = mutableSetOf()): Int? {
            val cls = api[owner] ?: return null
            if (!seen.add(owner)) return null
            cls.methods[method]?.let { return it }
            return cls.supers.firstNotNullOfOrNull { since(it, method, seen) }
        }

        val apks = apkDirectory.get().asFile.walk().filter { it.extension == "apk" }.toList()
        if (apks.isEmpty()) throw GradleException("No APK in ${apkDirectory.get()}")
        val tmp = temporaryDir
        for (apk in apks) {
            ZipFile(apk).use { zip ->
                for (entry in zip.entries()) {
                    if (!Regex("classes\\d*\\.dex").matches(entry.name)) continue
                    val dex = File(tmp, entry.name)
                    zip.getInputStream(entry).use { input -> dex.outputStream().use { input.copyTo(it) } }
                    val process = ProcessBuilder(dexdump.get().asFile.path, "-d", dex.path)
                        .redirectError(ProcessBuilder.Redirect.DISCARD)
                        .start()
                    var caller = ""
                    process.inputStream.bufferedReader(Charsets.ISO_8859_1).forEachLine { line ->
                        classDescriptor.matchEntire(line)?.let {
                            caller = deobfuscate[it.groupValues[1]] ?: it.groupValues[1]
                            return@forEachLine
                        }
                        val match = invoke.find(line) ?: return@forEachLine
                        if (caller.startsWith("androidx/") || caller.startsWith("android/support/")) {
                            return@forEachLine
                        }
                        val (owner, name, descriptor) = match.destructured
                        val method = name + descriptor
                        val level = since(owner, method)
                            // not declared: an inherited method of a non-public class, check the class instead
                            ?: api[owner]?.since
                            // not in the API at all. android/ classes that aren't are part of the app (e.g. the
                            // android.support AIDL classes of androidx.core).
                            ?: if (owner.startsWith("android/")) return@forEachLine else Int.MAX_VALUE
                        if (level <= min) return@forEachLine
                        val key = "$owner.$method"
                        val allowedBy = allowed.keys.firstOrNull { pattern ->
                            if (pattern.endsWith("*")) key.startsWith(pattern.dropLast(1)) else key == pattern
                        }
                        if (allowedBy != null) {
                            allowedSeen += allowedBy
                        } else {
                            violations.getOrPut(key) { level to sortedSetOf() }.second += caller
                        }
                    }
                    if (process.waitFor() != 0) throw GradleException("dexdump failed on ${entry.name} of $apk")
                    dex.delete()
                }
            }
        }

        val text = buildString {
            for ((key, value) in violations) {
                val level = if (value.first == Int.MAX_VALUE) "missing" else "API ${value.first}"
                appendLine("$key ($level), called from ${value.second.take(5).joinToString()}")
            }
            for (key in allowed.keys - allowedSeen) {
                appendLine("note: allowed reference $key is not referenced by this APK")
            }
        }
        report.get().asFile.writeText(text)
        if (violations.isNotEmpty()) {
            throw GradleException(
                "The APK calls platform methods that don't exist at minSdk $min. Avoid them, or add them to " +
                    "apiLevelCheck.allowed if they are unreachable on older versions:\n$text"
            )
        }
    }

    private fun parseApiVersions(file: File): Map<String, ApiClass> {
        val classes = HashMap<String, ApiClass>()
        fun level(value: String?, default: Int) = value?.substringBefore('.')?.toInt() ?: default
        SAXParserFactory.newInstance().newSAXParser().parse(file, object : DefaultHandler() {
            var name: String? = null
            var since = 1
            var methods = HashMap<String, Int>()
            var supers = ArrayList<String>()

            override fun startElement(uri: String?, localName: String?, qName: String, attributes: Attributes) {
                when (qName) {
                    "class" -> {
                        name = attributes.getValue("name")
                        since = level(attributes.getValue("since"), 1)
                        methods = HashMap()
                        supers = ArrayList()
                    }
                    "method" -> if (name != null) {
                        methods[attributes.getValue("name")] = level(attributes.getValue("since"), since)
                    }
                    "extends", "implements" -> if (name != null) supers += attributes.getValue("name")
                }
            }

            override fun endElement(uri: String?, localName: String?, qName: String) {
                if (qName == "class") {
                    classes[name!!] = ApiClass(since, methods, supers)
                    name = null
                }
            }
        })
        return classes
    }

    /**
     * Obfuscated to original class names (both in internal form, `a/b/C`) from an R8 mapping file.
     */
    private fun parseMapping(file: File): Map<String, String> {
        val classLine = Regex("""(\S+) -> (\S+):""")
        return file.useLines { lines ->
            lines.mapNotNull { classLine.matchEntire(it) }
                .associate { it.groupValues[2].replace('.', '/') to it.groupValues[1].replace('.', '/') }
        }
    }
}
