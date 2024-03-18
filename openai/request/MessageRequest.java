package openai.request;

public class MessageRequest {
	String role;
	String content;
	public MessageRequest(String content) {
		this.role = "user";
		this.content = content;
	}
}
