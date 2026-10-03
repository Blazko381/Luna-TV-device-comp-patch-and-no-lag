package app.morphe.patches.amazon.AmazonLunaTV

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.fingerprint.method.impl.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.builder.Label
import org.jf.dexlib2.builder.instruction.BuilderInstruction11n
import org.jf.dexlib2.builder.instruction.BuilderInstruction11x
import org.jf.dexlib2.builder.instruction.BuilderInstruction21t
import org.jf.dexlib2.builder.instruction.BuilderInstruction35c
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference

/**
 * Fingerprint wykrywający metodę w CodecUtils, w której inicjalizowany jest CodecConfig
 */
private object CodecUtilsFingerprint : MethodFingerprint(
    strings = listOf("adaptive-playback", "CodecConfig")
)

@Patch(
    name = "Luna Low Latency Codecs",
    description = "Forces Amazon Luna to avoid codecs not supporting low latency, reducing input lag (based on mocelet patch).",
    compatiblePackages = [
        CompatiblePackage("com.amazon.spiderpork")
    ]
)
object LunaLowLatencyPatch : BytecodePatch(
    setOf(CodecUtilsFingerprint)
) {
    override fun execute(context: BytecodeContext) {
        val result = CodecUtilsFingerprint.result
            ?: throw IllegalStateException("Codec configuration method not found in APK.")

        val mutableMethod = result.mutableMethod
        val instructions = mutableMethod.implementation?.instructions
            ?: throw IllegalStateException("Method implementation is null.")

        // 1. Znajdujemy instrukcję wywołania konstruktora CodecConfig (gdzie obiekt trafia do rejestru v0)
        var targetIndex = -1
        for (i in 0 until instructions.size) {
            val insn = instructions[i]
            if (insn.opcode == Opcode.INVOKE_DIRECT) {
                val methodRef = (insn as? BuilderInstruction35c)?.reference as? MethodReference
                if (methodRef?.definingClass?.contains("CodecConfig") == true && methodRef.name == "<init>") {
                    targetIndex = i
                    break
                }
            }
        }

        if (targetIndex == -1) {
            throw IllegalStateException("CodecConfig constructor invocation not found.")
        }

        // 2. Definiujemy referencję do metody isLowLatency()Z z klasy CodecConfig
        val isLowLatencyMethod = ImmutableMethodReference(
            "Lcom/amazon/spiderpork/streamconfig/codec/CodecConfig;",
            "isLowLatency",
            emptyList(),
            "Z"
        )

        // 3. Tworzymy etykietę skoku (odpowiednik :low_latency_supported ze smali)
        val lowLatencySupportedLabel = Label()

        // 4. Wstrzykujemy instrukcje dokładnie tak, jak w pliku diff moceleta tuż po wywołaniu konstruktora:
        
        // invoke-virtual {v0}, Lcom/amazon/spiderpork/streamconfig/codec/CodecConfig;->isLowLatency()Z
        val invokeInsn = BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL,
            1, 0, 0, 0, 0, 0,
            isLowLatencyMethod
        )
        
        // move-result v1
        val moveResultInsn = BuilderInstruction11x(Opcode.MOVE_RESULT, 1)

        // if-nez v1, :low_latency_supported
        val ifNezInsn = BuilderInstruction21t(Opcode.IF_NEZ, 1, lowLatencySupportedLabel)

        // const/4 v1, 0x0
        val constInsn = BuilderInstruction11n(Opcode.CONST_4, 1, 0)

        // return-object v1
        val returnInsn = BuilderInstruction11x(Opcode.RETURN_OBJECT, 1)

        // Wstawiamy instrukcje sekwencyjnie zaraz po konstruktorze
        var insertPos = targetIndex + 1
        instructions.add(insertPos++, invokeInsn)
        instructions.add(insertPos++, moveResultInsn)
        instructions.add(insertPos++, ifNezInsn)
        instructions.add(insertPos++, constInsn)
        instructions.add(insertPos++, returnInsn)
        
        // Przypisujemy etykietę :low_latency_supported do kolejnej instrukcji
        instructions.add(insertPos, lowLatencySupportedLabel)
    }
}