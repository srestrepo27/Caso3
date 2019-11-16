package Cliente;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator 
{
	private LoadGenerator generator;
	
	
	public Generator()
	{
		Task work= createTask();
		int number=400;
		int gap=20;
		generator= new LoadGenerator("Client-Server Load", number, work, gap);
		
		generator.generate();
	}
	private Task createTask()
	{
		return new ClienteSeguro();
	}
	public static void main(String[] args)
	{
		Generator gen= new Generator();
	}
	
}
