// Rebase the single memory block to the C64 load address $0801.
//@category C64
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class RebaseToC64Load extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        MemoryBlock[] blocks = mem.getBlocks();
        if (blocks.length == 0) { println("No memory blocks"); return; }

        MemoryBlock block = blocks[0];
        Address newStart = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(0x0801);

        if (block.getStart().equals(newStart)) {
            println("Already at $0801, nothing to do.");
            return;
        }

        println("Moving block from " + block.getStart() + " to " + newStart);
        mem.moveBlock(block, newStart, monitor);
        println("Done. Block now at " + block.getStart());
    }
}
