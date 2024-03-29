import ghidra.GhidraUtility;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SourceType;

import java.lang.reflect.Type;
import java.net.http.HttpClient;
import java.util.Map;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import openai.OpenAiUtility;
import openai.Configuration;

public class GptOneFunction extends GhidraScript {
	Gson gson = new Gson();
	HttpClient client = HttpClient.newHttpClient();
	Configuration configuration = new Configuration();
	String model = "gpt-4-turbo-preview";
//	String model = "gpt-3.5-turbo";
	String promptString = "This is a decompiled function from Ghidra; analyze it."
			+ "Your reply must be non-nested (i.e. FLAT) JSON." + "Give the function a better name."
			+ "\"functionName\" is the key for the new function name."
			+ "Give the parameters and variables better names."
			+ "All renames will have original name (without type info) as key and new name (without type info) as value.";

	@Override
	protected void run() throws Exception {
		DecompileResults decompiledFunction = this.getCurrentDecompiledFunction();
		HighFunction highFunction = decompiledFunction.getHighFunction();

		// Create the request body
		String decompiledCode = decompiledFunction.getDecompiledFunction().getC();
		Map<String, String> responseMap = OpenAiUtility.synchronousRequest(promptString, decompiledCode, model,
				configuration, this);

		GhidraUtility.renameHighFunctionVariables(highFunction, responseMap, this);
	}

	protected DecompileResults getCurrentDecompiledFunction() {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function currentFunction = functionManager.getFunctionContaining(currentAddress);

		if (currentFunction == null) {
			println("No function at the current location.");
			return null;
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		DecompileResults results = decompiler.decompileFunction(currentFunction, 30, monitor);
		if (!results.decompileCompleted()) {
			println("Decompilation failed.");
			return null;
		}
		return results;
	}

	public Map<String, String> jsonToMap(String jsonResponse) {
		// Remove the code block syntax if it's included in the response
		jsonResponse = jsonResponse.replace("```json\n", "").replace("\n```", "");
		Type type = new TypeToken<Map<String, String>>() {
		}.getType();

		Gson dupeGson = new GsonBuilder().registerTypeAdapter(Map.class, new JsonDeserializer<Map<String, Object>>() {
			@Override
			public Map<String, Object> deserialize(JsonElement json1, Type typeOfT, JsonDeserializationContext context)
					throws JsonParseException {
				return new Gson().fromJson(json1, typeOfT);
			}
		}).create();

		Map<String, String> responseMap = dupeGson.fromJson(jsonResponse, type);
		return responseMap;
	}
}
