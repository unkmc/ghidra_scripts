
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

public class GptAllFunctions extends GhidraScript {
	Configuration configuration = new Configuration();
	String model = "gpt-3.5-turbo";
	int maxFunctionsToProcess = 50;
	String promptString = "This is a decompiled function from Ghidra; analyze it."
			+ "Give the function a better name. Give the parameters and variables better names."
			+ "Do not include variable type, only name." + "Your repy must be non-nested (i.e. FLAT) JSON."
			+ "\"functionName\" is the key for the new function name."
			+ "All other renames will have original name (without type) as key and new name (without type) as value.";

	@Override
	protected void run() throws Exception {
		int functionsProcessed = 0;
		Program program = this.getCurrentProgram();
		FunctionManager functionManager = program.getFunctionManager();
		AcyclicCallGraphBuilder builder = new AcyclicCallGraphBuilder(program, true);
		AbstractDependencyGraph<Address> graph = builder.getDependencyGraph(monitor);
		println("got call graph");

		Address address = graph.pop();
		while (address != null && functionsProcessed < maxFunctionsToProcess) {
			Function function = functionManager.getFunctionAt(address);
			if (function.getSignatureSource() == SourceType.USER_DEFINED) {
				println("Function " + function.getName() + " has already been touched.");
				address = graph.pop();
				println("There are " + graph.size() + " items left in the graph.");
				continue;
			}
			DecompileResults decompiledFunction = GhidraUtility.getCurrentDecompiledFunction(function, this);
			HighFunction highFunction = decompiledFunction.getHighFunction();

			// Create the request body
			String decompiledCode = decompiledFunction.getDecompiledFunction().getC();
			Map<String, String> responseMap = OpenAiUtility.synchronousRequest(promptString, decompiledCode, model,
					configuration, this);
//			println("Got response map: " + responseMap);

//			GhidraUtility.renameFunctionVariables(function, responseMap, this);
			try {
				GhidraUtility.renameHighFunctionVariables(highFunction, responseMap, this);
			} catch (NullPointerException e) {
				if (e.getMessage() != null && e.getMessage().contains("highFunction")) {
					System.err.println("highFunction value was set to null during execution, skipping function.");
				} else {
					throw e;
				}
			}
			address = graph.pop();
			functionsProcessed++;
			println("Processed " + functionsProcessed + " out of maximum " + maxFunctionsToProcess);
			println("There are " + graph.size() + " items left in the graph.");
		}
	}
}
