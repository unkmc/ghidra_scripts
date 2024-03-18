import ghidra.GhidraUtility;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;

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
//	String model = "gpt-4-turbo-preview";
	String model = "gpt-3.5-turbo";

	@Override
	protected void run() throws Exception {
		DecompileResults decompiledFunction = this.getCurrentDecompiledFunction();
		String decompiledCode = decompiledFunction.getDecompiledFunction().getC();

		String threadId = OpenAiUtility.createThread(configuration, this);
		if (threadId == null) {
			throw new Exception("Unable to create thread.");
		}
		configuration.setThreadId(threadId);

		String messageId = OpenAiUtility.createMessage(decompiledCode, threadId, configuration, this);
		if (messageId == null) {
			throw new Exception("Unable to create message.");
		}

		String runId = OpenAiUtility.createRun(model, configuration, this);
		if (runId == null) {
			throw new Exception("Unable to create run.");
		}

		Thread.sleep(5000);
		String runStatus = OpenAiUtility.getRunStatus(runId, configuration, this);
		while (runStatus.equals("queued") || runStatus.equals("in_progress")) {
			Thread.sleep(2000); // Don't get throttled
			runStatus = OpenAiUtility.getRunStatus(runId, configuration, this);
		}
		if (!runStatus.equals("completed")) {
			println("Run status was " + runStatus + " so I guess the run failed.");
			return;
		}

		String fullMessageResponse = OpenAiUtility.getLatestMessage(messageId, configuration, this);
		String responseContent = OpenAiUtility.extractContentFromGptResponse(fullMessageResponse, this);
		println("Response Content: " + responseContent);

		Map<String, String> responseMap = jsonToMap(responseContent);
		println("Response Map: " + responseMap);

		// get current function and list of associated variables
		// TODO: this doesn't seem to get "pointer" type variables for some reason
//		Function function = decompiledFunction.getFunction();
//		GhidraUtility.renameFunctionVariables(function, responseMap, this);

		HighFunction highFunction = decompiledFunction.getHighFunction();
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
