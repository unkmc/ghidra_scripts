package openai.request;

import java.util.ArrayList;

public class CompletionRequest {
	public String model;
	public ArrayList<ChatMessage> messages;
	public double temperature;
//	public ChatResponseFormat response_format=new ChatResponseFormat();

	public CompletionRequest(String model) {
		this.model = model;
		this.temperature = 0.2;
//		this.response_format.type = "json_object";
		messages = new ArrayList<ChatMessage>();
	}
}
