
import java.util.Map;

import ghidra.GhidraUtility;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.graph.AbstractDependencyGraph;
import openai.Configuration;
import openai.OpenAiUtility;
import ghidra.program.model.address.Address;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;

public class ReadClipboardStack extends GhidraScript {

	@Override
    public void run() throws Exception {
        String clipboardContent = getClipboardContent();
        if (clipboardContent == null) {
            println("No clipboard content found or unable to access clipboard.");
            return;
        }

        // Process each line from the clipboard content
        String[] lines = clipboardContent.split("\n");
        for (String line : lines) {
            String[] tokens = line.split("\\s+");
            if (tokens.length == 0) continue;

            String firstToken = tokens[0];
            Address address = parseAddress(firstToken);
            if (address != null) {
                Function function = getFunctionContaining(address);
                if (function != null) {
                    println("Address " + firstToken + " is inside function: " + function.getName());
                } else {
                    println("Address " + firstToken + " is not inside any known function.");
                }
            }
        }
    }
	
    private String getClipboardContent() {
        try {
            return (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
