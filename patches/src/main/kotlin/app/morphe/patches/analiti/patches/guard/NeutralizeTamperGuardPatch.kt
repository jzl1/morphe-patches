package lab.analiti.patches.guard

import app.morphe.patcher.patch.rawResourcePatch
import lab.analiti.patches.shared.COMPATIBILITY_ANALITI
import net.fornwall.jelf.ElfFile
import net.fornwall.jelf.ElfSymbol
import java.io.RandomAccessFile

private const val GLUE_LIB = "lib/arm64-v8a/libiperf-jni-glue.so"

/**
 * ARM64 `mov w0, #0` + `ret` — the ABI's "return NULL" stub.
 */
private val ARM64_RETURN_NULL = byteArrayOf(
    0x00, 0x00, 0x80.toByte(), 0xD2.toByte(),
    0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte(),
)

/**
 * analiti's anti-tamper response is a native fork bomb, not a simple abort.
 *
 * `libiperf-jni-glue.so` verifies the signing certificate of the installed package
 * against an embedded allow-list (Play/Amazon/debug). When the check fails it calls
 * `doThat8Delayed`, which recursively spawns two copies of itself with `pthread_create`.
 * Thread count grows exponentially (2^n) and the process dies of resource exhaustion
 * roughly ten seconds after launch.
 *
 * `doThat8Delayed` is *only* ever used as a `pthread_create` start routine — it is
 * never `BL`-called — and every one of the ten spawn sites passes it. Returning
 * immediately from its entry point therefore disables all of them at once, without
 * touching the legitimate iperf3 threading code.
 *
 * The symbol is present in `.dynsym` (it is a globally exported function), so it is
 * located by name rather than by a hardcoded file offset. That keeps the patch
 * working across minor rebuilds of the library.
 */
@Suppress("unused")
val neutralizeTamperGuardPatch = rawResourcePatch(
    name = "Neutralize tamper fork bomb",
    description = "Stops the native anti-tamper response that spawns unbounded threads " +
            "and crashes the app a few seconds after launch on a repackaged build.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_ANALITI)

    execute {
        val lib = get(GLUE_LIB, true)
        val elf = ElfFile.from(lib)

        val symbol = elf.dynamicSymbolTableSection.symbols.firstOrNull { candidate ->
            candidate.getName() == "doThat8Delayed" &&
                    candidate.getType() == ElfSymbol.STT_FUNC.toInt()
        } ?: throw IllegalStateException(
            "Could not find doThat8Delayed in $GLUE_LIB. The library layout has changed."
        )

        // st_value is the virtual address. For this shared object the .text segment is
        // mapped at a 1:1 file offset, but derive the real file offset from the section
        // that contains the symbol so the patch does not silently corrupt the file if
        // the linker ever changes that relationship.
        val fileOffset = fileOffsetOf(elf, symbol)

        RandomAccessFile(lib, "rw").use { raf ->
            raf.seek(fileOffset)
            raf.write(ARM64_RETURN_NULL)
        }
    }
}

/**
 * Translate a symbol's virtual address into an offset inside the ELF file.
 *
 * Walks the section headers and finds the one whose address range contains the
 * symbol, then applies the section's own address-to-offset delta.
 */
private fun fileOffsetOf(elf: ElfFile, symbol: ElfSymbol): Long {
    var index = 0
    while (true) {
        val section = try {
            elf.getSection(index)
        } catch (e: Exception) {
            null
        } ?: break

        val header = section.header
        val address = header.sh_addr
        if (address != 0L && header.sh_size > 0) {
            if (symbol.st_value >= address && symbol.st_value < address + header.sh_size) {
                return header.sh_offset + (symbol.st_value - address)
            }
        }
        index++
    }

    // Fall back to the identity mapping used by the toolchain that built this library.
    return symbol.st_value
}
