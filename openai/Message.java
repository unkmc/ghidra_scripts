package openai;

import java.util.List;
import java.util.Map;

public class Message {
	public String id;
	public String object;
	public int createdAt;
	public String threadId;
	public String role;
	public List<MessageContent> content;
	public String assistantId;
	public String runId;
	public List<String> fileIds;
	public Map<String, String> metadata;
}