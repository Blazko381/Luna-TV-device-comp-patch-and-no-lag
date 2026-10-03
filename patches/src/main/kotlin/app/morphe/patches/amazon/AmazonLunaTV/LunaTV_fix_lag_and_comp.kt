package app.morphe.patches.amazon.AmazonLunaTV

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.fingerprint.method.impl.MethodFingerprint
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11n
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction11x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21t
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction35c
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

        // Poprawka: w ReVanced Patcher właściwość zwracająca mutowalną metodę to .method, a nie .mutableMethod
        val mutableMethod = result.method
        val instructions = mutableMethod.implementation?.instructions
            ?: throw IllegalStateException("Method implementation is null.")

        // 1. Znajdujemy instrukcję wywołania konstruktora CodecConfig (gdzie obiekt trafia do rejestru v0)
        var targetIndex = -1
        for (i in 0 until instructions.size) {
            val insn = instructions[i]
            if (insn.opcode == Opcode.INVOKE_DIRECT) {
                val methodRef = (insn as? org.jf.dexlib2.iface.instruction.formats.Instruction35c)?.reference as? MethodReference
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

        // 3. Tworzymy niemutowalne instrukcje do wstrzyknięcia
        
        // invoke-virtual {v0}, Lcom/amazon/spiderpork/streamconfig/codec/CodecConfig;->isLowLatency()Z
        val invokeInsn = ImmutableInstruction35c(
            Opcode.INVOKE_VIRTUAL,
            1, 0, 0, 0, 0, 0,
            isLowLatencyMethod
        )
        
        // move-result v1
        val moveResultInsn = ImmutableInstruction11x(Opcode.MOVE_RESULT, 1)

        // if-nez v1, +4 (przeskakuje const/4 oraz return-object do kolejnej instrukcji w kodzie)
        val ifNezInsn = ImmutableInstruction21t(Opcode.IF_NEZ, 1, 4)

        // const/4 v1, 0x0
        val constInsn = ImmutableInstruction11n(Opcode.CONST_4, 1, 0)

        // return-object v1
        val returnInsn = ImmutableInstruction11x(Opcode.RETURN_OBJECT, 1)

        // 4. Wstawiamy instrukcje sekwencyjnie zaraz po wywołaniu konstruktora
        var insertPos = targetIndex + 1
        instructions.add(insertPos++, invokeInsn)
        instructions.add(insertPos++, moveResultInsn)
        instructions.add(insertPos++, ifNezInsn)
        instructions.add(insertPos++, constInsn)
        instructions.add(insertPos, returnInsn)
    }
}