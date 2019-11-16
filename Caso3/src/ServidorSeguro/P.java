package ServidorSeguro;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class P {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */
	public static int perdidas=0;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		int i=0;
		int ip=0;
		int cantidad = 0;
		
		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		
		 ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());		
		System.out.println("Establezca el numero de conexiones simultaneas");
		cantidad = Integer.parseInt(br.readLine());
		
		// Crea el archivo de log
		File file = null;
		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor);
		String ruta = "./R1.txt";
   
        file = new File(ruta);
        if (!file.exists()) {
            file.createNewFile();
        }
        
        FileWriter fw = new FileWriter(file);
        fw.close();
        
        D.init(certSer, keyPairServidor, file);
        
		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println(MAESTRO + "Socket creado.");
        
		ExecutorService pool= Executors.newFixedThreadPool(cantidad);
		while(true)
		{
			pool.execute(new D(ss.accept(), i++));
		}
	}

}
