import java.net.http.HttpClient;

import com.google.gson.Gson;

import ghidra.app.script.GhidraScript;
import openai.Configuration;

public class GptFunctionTreeRoot extends GhidraScript {
	Gson gson = new Gson();
	HttpClient client = HttpClient.newHttpClient();
	Configuration configuration = new Configuration();
	String model = "gpt-3.5-turbo";
	
	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		
	}

}
