package openai;

public class ConfigurationExample {
	// Fill these out
	public String apiKey = "apiKey";
	public String assistantId = "assistantId";

	public String completionsUri = "https://api.openai.com/v1/chat/completions";
	public String assistantThreadsUri = "https://api.openai.com/v1/threads";
	public String assistantThreadId;
	public String assistantMessagesUri;
	public String assistantRunsUri;

	public void setThreadId(String threadId) {
		assistantThreadId = threadId;
		assistantMessagesUri = "https://api.openai.com/v1/threads/" + assistantThreadId + "/messages";
		assistantRunsUri = "https://api.openai.com/v1/threads/" + assistantThreadId + "/runs";
	}
}
