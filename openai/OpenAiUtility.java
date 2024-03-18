package openai;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import ghidra.app.script.GhidraScript;
import openai.request.ChatMessage;
import openai.request.CompletionRequest;
import openai.request.MessageRequest;
import openai.response.CompletionResponse;

public class OpenAiUtility {
	static Gson gson = new Gson();
	static HttpClient client = HttpClient.newHttpClient();
	static Map<String, String> emptyMap = new HashMap<>();

	public static Map<String, String> synchronousRequest(String promptString, String decompiledCode, String model,
			Configuration configuration, GhidraScript script) throws IOException, InterruptedException {
		// Create the request body
		CompletionRequest requestObject = new CompletionRequest(model);
		requestObject.messages.add(new ChatMessage(promptString));
		requestObject.messages.add(new ChatMessage(decompiledCode));
		String jsonRequest = gson.toJson(requestObject);

//		script.println("Sending request to GPT:");
//		script.println(jsonRequest);
		HttpRequest request = HttpRequest.newBuilder().header("Authorization", "Bearer " + configuration.apiKey)
				.uri(URI.create("https://api.openai.com/v1/chat/completions"))
				.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(jsonRequest))
				.build();

		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		String jsonResponse = response.body();
//		script.println("Response from OpenAI: " + jsonResponse);

		CompletionResponse responseBody = gson.fromJson(jsonResponse, CompletionResponse.class);

		if (responseBody.choices == null) {
//			script.println("Reponse choices was null, request probably failed.");
			return emptyMap;
		}
		if (responseBody.choices.isEmpty()) {
//			script.println("No response in completion: " + responseBody);
			return emptyMap;
		}
		String content = responseBody.choices.get(0).message.content;
//		script.println("Content from response: " + content);

		Map<String, String> responseMap = jsonToMap(content);
//		script.println("Response Map: " + responseMap);
		return responseMap;
	}

	public static String getLatestMessage(String lastMessageId, Configuration configuration, GhidraScript script)
			throws IOException, InterruptedException {
		String fullUri = configuration.assistantMessagesUri;// + "?after=" + lastMessageId + "&limit=2";
		script.println("Requesting next message with URI: " + fullUri);
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(fullUri))
				.header("Authorization", "Bearer " + configuration.apiKey).header("Content-Type", "application/json")
				.header("OpenAI-Beta", "assistants=v1").GET().build();
		HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
		String responseJson = response.body();
//		script.println("Response from OpenAI message API: " + responseJson);
		return responseJson;
	}

	public static String createMessage(String decompiledCode, String threadId, Configuration configuration,
			GhidraScript script) throws InterruptedException, IOException {
		MessageRequest message = new MessageRequest(decompiledCode);
		String jsonMessagesRequest = gson.toJson(message);

//		script.println("Sending messages request to GPT:");
//		script.println(jsonMessagesRequest);

		HttpRequest addMessageRequest = HttpRequest.newBuilder().uri(URI.create(configuration.assistantMessagesUri))
				.header("Authorization", "Bearer " + configuration.apiKey).header("Content-Type", "application/json")
				.header("OpenAI-Beta", "assistants=v1").POST(HttpRequest.BodyPublishers.ofString(jsonMessagesRequest))
				.build();

		HttpResponse<String> messagesResponse = client.send(addMessageRequest, BodyHandlers.ofString());
		String messagesResponseJson = messagesResponse.body();
//		script.println("Response from OpenAI messages API: " + messagesResponseJson);

		MessageResponseBody responseBody = gson.fromJson(messagesResponseJson, MessageResponseBody.class);
		String id = responseBody.id;
//		script.println("ID from message response: " + id);
		return id;
	}

	public static String createRun(String model, Configuration configuration, GhidraScript script)
			throws IOException, InterruptedException {
		RunRequest runsRequestBody = new RunRequest(configuration.assistantId, model);
		String jsonRunsRequest = gson.toJson(runsRequestBody);
		HttpRequest runsRequest = HttpRequest.newBuilder().uri(URI.create(configuration.assistantRunsUri))
				.header("Authorization", "Bearer " + configuration.apiKey).header("Content-Type", "application/json")
				.header("OpenAI-Beta", "assistants=v1").POST(HttpRequest.BodyPublishers.ofString(jsonRunsRequest))
				.build();
		HttpResponse<String> runsResponse = client.send(runsRequest, BodyHandlers.ofString());
		String runsResponseJson = runsResponse.body();
//		script.println("Response from OpenAI runs API: " + runsResponseJson);

		RunResponseBody responseBody = gson.fromJson(runsResponseJson, RunResponseBody.class);
		String id = responseBody.id;
//		script.println("ID from runs response: " + id);
		return id;
	}

	public static String getRunStatus(String runId, Configuration configuration, GhidraScript script)
			throws IOException, InterruptedException {
		String runsUri = configuration.assistantRunsUri + "/" + runId;
		HttpRequest runsRequest = HttpRequest.newBuilder().uri(URI.create(runsUri))
				.header("Authorization", "Bearer " + configuration.apiKey).header("Content-Type", "application/json")
				.header("OpenAI-Beta", "assistants=v1").GET().build();
		HttpResponse<String> runsResponse = client.send(runsRequest, BodyHandlers.ofString());
		String runsResponseJson = runsResponse.body();
//		script.println("Response from OpenAI runs API: " + runsResponseJson);
		RunResponseBody responseBody = gson.fromJson(runsResponseJson, RunResponseBody.class);
		String status = responseBody.status;
//		script.println("Status from response: " + status);
		return status;
	}

	public static String createThread(Configuration configuration, GhidraScript script)
			throws IOException, InterruptedException {
		HttpRequest threadRequest = HttpRequest.newBuilder().uri(URI.create(configuration.assistantThreadsUri))
				.header("Authorization", "Bearer " + configuration.apiKey).header("Content-Type", "application/json")
				.header("OpenAI-Beta", "assistants=v1").POST(HttpRequest.BodyPublishers.ofString("")).build();
		HttpResponse<String> threadResponse = client.send(threadRequest, BodyHandlers.ofString());
		String threadResponseJson = threadResponse.body();
//		script.println("Response from OpenAI threads API: " + threadResponseJson);

		ThreadResponseBody responseBody = gson.fromJson(threadResponseJson, ThreadResponseBody.class);
		String id = responseBody.id;
//		script.println("ID from threads response: " + id);
		return id;
	}

	public static String extractContentFromGptResponse(String jsonResponse, GhidraScript script) {
		Type openAiResponseType = new TypeToken<OpenAiResponse<Message>>() {
		}.getType();
		OpenAiResponse<Message> responseBody = gson.fromJson(jsonResponse, openAiResponseType);
		if (responseBody.data.size() == 0) {
//			script.println("No data found in message response.");
			return "";
		}
		if (responseBody.data.getFirst().content.size() == 0) {
//			script.println("No content found in first message.");
			return "";
		}
		return responseBody.data.getFirst().content.getFirst().text.value;
	}

	public static Map<String, String> jsonToMap(String jsonResponse) {
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
