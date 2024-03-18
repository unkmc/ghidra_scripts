package openai;


public class RunRequest {
	String assistant_id;
	String model;

	public RunRequest(String assistant_id, String model) {
		this.assistant_id = assistant_id;
		this.model = model;
	}
}
