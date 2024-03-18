package openai.request;

public class ChatMessage {

	public String role;
	public String content;

	public ChatMessage(String content) {
		this.role = "user";
		this.content = content;
	}
}
