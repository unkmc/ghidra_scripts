package openai;

import java.util.List;

public class OpenAiResponse<T> {
	public List<T> data;
	public String object;
	public String firstId;
	public String lastId;
	public boolean hasMore;
}
