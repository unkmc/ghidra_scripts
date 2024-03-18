package ghidra;

import java.util.Iterator;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.pcode.HighFunctionDBUtil;

public class GhidraUtility {
	public static DecompileResults getCurrentDecompiledFunction(Function function, GhidraScript script) {
		if (function == null) {
			script.println("No function at the current location.");
			return null;
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(script.getCurrentProgram());

		DecompileResults results = decompiler.decompileFunction(function, 30, script.getMonitor());
		if (!results.decompileCompleted()) {
			script.println("Decompilation failed.");
			return null;
		}

		return results;
	}

	public static void renameFunctionVariables(Function function, Map<String, String> variableMap, GhidraScript script)
			throws DuplicateNameException, InvalidInputException {
		if (function == null) {
			script.println("Function was null.");
			return;
		}

		if (function.getSignatureSource() != SourceType.USER_DEFINED && variableMap.containsKey("functionName")) {
			String originalName = function.getName();
			String newName = originalName + "_" + variableMap.get("functionName");
			script.println("Function will be renamed, " + originalName + " -> " + newName);
			function.setName(newName, SourceType.USER_DEFINED);
			function.setSignatureSource(SourceType.USER_DEFINED);
		}

		// iterate through all variables for current function
		Variable[] vars = function.getAllVariables();
		for (int i = 0; i < vars.length; i++) {
			Variable v = vars[i];
			String variableName = v.getName();
			if (variableMap.containsKey(variableName)) {
				String newName = variableMap.get(variableName);
				script.println("Renaming " + variableName + " to " + newName);
				v.setName(newName, SourceType.USER_DEFINED);
			} else {
				script.println("Variable not found in map: " + variableName);
			}
		}
	}

	public static void renameHighFunctionVariables(HighFunction highFunction, Map<String, String> variableMap,
			GhidraScript script) throws DuplicateNameException, InvalidInputException {
		Function function = highFunction.getFunction();
		if (variableMap.containsKey("functionName")) {
			String originalName = function.getName();
			if (function.getSignatureSource() == SourceType.USER_DEFINED) {
				script.println("Function " + originalName + " has already been touched.");
				return;
			}
			String newName = originalName + "_" + variableMap.get("functionName");
			script.println("Function will be renamed, " + originalName + " -> " + newName);
			function.setName(newName, SourceType.USER_DEFINED);
			function.setSignatureSource(SourceType.USER_DEFINED);
		}

		Iterator<HighSymbol> globalSymbols = highFunction.getGlobalSymbolMap().getSymbols();
		while (globalSymbols.hasNext()) {
			HighSymbol symbol = globalSymbols.next();
			String originalName = symbol.getName();
			if (!variableMap.containsKey(originalName)) {
				continue;
			}
			String newName = originalName + "_" + variableMap.get(originalName);
			try {
				HighFunctionDBUtil.updateDBVariable(symbol, newName, symbol.getDataType(), SourceType.USER_DEFINED);
			} catch (ghidra.util.exception.InvalidInputException e) {
				script.println("Global symbol: " + symbol.getName() + " could not be renamed: " + e.getMessage());
			} catch (java.lang.NullPointerException e) {
				script.println("Global symbol: " + symbol.getName() + " could not be renamed: " + e.getMessage());
			}
			script.println("Renamed global symbol: " + symbol.getName() + " -> " + newName);
		}

		Map<String, HighSymbol> localSymbols = highFunction.getLocalSymbolMap().getNameToSymbolMap();
		for (var symbolEntry : localSymbols.entrySet()) {
			if (!variableMap.containsKey(symbolEntry.getKey())) {
				continue;
			}
			HighSymbol symbol = symbolEntry.getValue();
			String originalName = symbol.getName();
			String newName = originalName + "_" + variableMap.get(originalName);
			try {
				HighFunctionDBUtil.updateDBVariable(symbol, newName, symbol.getDataType(), SourceType.USER_DEFINED);
			} catch (ghidra.util.exception.InvalidInputException e) {
				script.println("Local symbol: " + symbol.getName() + " could not be renamed: " + e.getMessage());
			} catch (java.lang.NullPointerException e) {
				script.println("Local symbol: " + symbol.getName() + " could not be renamed: " + e.getMessage());
			}
			script.println("Renamed local symbol: " + symbol.getName() + " -> " + newName);
		}
	}
}
