package openai;

import java.util.ArrayList;


public class OpenAiRequest {
	String model;
	public ArrayList<Message> messages;

	public OpenAiRequest() {
		this.model = "gpt-4-0125-preview";
		this.messages = new ArrayList<>();
	}
}
