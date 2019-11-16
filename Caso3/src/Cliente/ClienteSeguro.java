package Cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import ServidorSeguro.D;
import ServidorSeguro.P;
import uniandes.gload.core.Task;

public class ClienteSeguro extends Task{
	/**
	 * Constante de hola
	 */
	public final static String HOLA="HOLA";
	
	/**
	 * constante ok
	 */
	public final static String OK="OK";
	
	/**
	 * constante del algoritmo de cifrado RSA
	 */
	public final static String RSA="RSA";
	
	/**
	 * constante del algoritmo de cifrado AES
	 */
	public final static String AES="AES";
	
	/**
	 * constante para el mensaje de algoritmos
	 */
	public final static String ALGORITMOS="ALGORITMOS";
	
	/**
	 * cosntante para el mensaje de error
	 */
	public final static String ERROR="ERROR";
	
	/**
	 * algortimo de cifrado de HMAC
	 */
	public final static String HMAC="HMACSHA512";
	
	/**
	 * 
	 */
	private static X509Certificate certSer;
	
	/**
	 * llave privada
	 */
	private static SecretKey privateKey;
	
	/**
	 * el estado de la comunicación
	 */
	private static boolean state;
	
	/**
	 * se inicializa el estado de la comunicación en falso
	 */
	public ClienteSeguro() {
		state = false;
	}
	
	/**
	 * método que dado un algoritmo cifra un mensaje
	 * Este método lo utilzamos para cifrar de manera simetrica  
	 * @param texto el texto que se quiere cifrar
	 * @param algoritmo el algoritmo con el cual se va a cifrar
	 * @return el mensaje cifrado
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static String cifrar(String texto, String algoritmo){
		if(texto.length()%4!=0) {
			for(int i=0;i<texto.length()%4;i++)
				texto += "0";
		}
		Cipher cifrador;
		try {
			cifrador = Cipher.getInstance(algoritmo);
			cifrador.init(Cipher.ENCRYPT_MODE,privateKey);
			byte ba[] = cifrador.doFinal(DatatypeConverter.parseBase64Binary(texto));
			return DatatypeConverter.printBase64Binary(ba);
		}catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * método para descifrar de manera simetrica con el algoritmo enviado por parametro
	 * @param texto el texto que se quiere cifrar
	 * @param algoritmo el algoritmo con el cual se va a descrifrar
	 * @return el mensaje descifrado
	 */
	public static String descifrar( String texto, String algoritmo){
		try{
			Cipher cifradorAES=Cipher.getInstance(algoritmo);
			cifradorAES.init(Cipher.DECRYPT_MODE,privateKey);
			byte serverAns1[] = cifradorAES.doFinal(DatatypeConverter.parseBase64Binary(texto));
			return DatatypeConverter.printBase64Binary(serverAns1);
		}catch(Exception e){
			System.out.println("Exception " + e.getMessage());
			return null;
		}
	}

	/**
	 * 
	 * @param contenido
	 */
	public static void imprimir(byte contenido[]) {
		int i = 0;
		for(; i < contenido.length - 1;++i) 
			System.out.println(contenido[i] + " ");
		System.out.println(contenido[i] + " ");
	}
	public static void main(String[] args)
	{
		
	
	}
	
	/**
	 * Procesar.
	 *
	 * @param pIn the in
	 * @param pOut the out
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws CertificateException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static void procesar(BufferedReader pIn, PrintWriter pOut) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, CertificateException, IllegalBlockSizeException, BadPaddingException {
		//se empieza la comunicación con el servidor
		 pOut.println(HOLA);
		 String line=pIn.readLine();
		 String answer ="";
		 System.out.println("cliente recibio-" + line + "-continuando.");
		 
		 if(line.equals(OK)&& !state)
		 {
			 answer = ALGORITMOS+":"+AES+":"+RSA+":"+HMAC;
			 pOut.println(answer);
			 System.out.println("cliente envió-" + answer + "-continuando.");
			 state = !state;
		 }
		 
		 line = pIn.readLine();
		 System.out.println("cliente recibio-" + line + "-continuando.");
		 if(line.equals(OK)&& state)
		 {
			 String certificado=pIn.readLine();
			 if(certificado!=null)
			 {
				 //se lee el certificado del servidor
				 byte[] certificadoServidorBytes = DatatypeConverter.parseBase64Binary(certificado);
				 CertificateFactory creator = CertificateFactory.getInstance("X.509");
				 InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
				 certSer = (X509Certificate) creator.generateCertificate(in);
				 System.out.println("Certificado Servidor: " + certSer);
				 certSer.checkValidity();
				 System.out.println("Certificado válido");

				 //se crea la llave simetrica para la comunicación
				 privateKey = KeyGenerator.getInstance(AES).generateKey();
				 byte key[] = privateKey.getEncoded();

				 //se encripta con la llave publica del servidor
				 Cipher cifradorRSA=Cipher.getInstance(RSA);
				 cifradorRSA.init(Cipher.ENCRYPT_MODE,certSer.getPublicKey());
				 byte encryptedKey[] = cifradorRSA.doFinal(key);
				 answer = DatatypeConverter.printBase64Binary(encryptedKey);
				 pOut.println(answer);
				 System.out.println("cliente envió llave simétrica-" + answer + "-continuando.");


				 //se envia el reto
				 answer = "casa";
				 pOut.println(answer);
				 System.out.println("cliente envió reto-" + answer + "-continuando.");

				 //se lee  la respuesta del reto por parte del servidor
				 line = pIn.readLine();
				 line = descifrar(line,AES);
				 System.out.println("cliente recibio reto-" + line + "-continuando.");

				 //Si son iguales continuo
				 if(line.equals(answer))
					 answer = OK;
				 else {
					 answer = ERROR;
					 pOut.println(answer);
					 return;
				 }
				 //muestra que la respuesta recibida ha sido correcta
				 pOut.println(answer);

				 //se envia la cedula
				 answer = cifrar("001005755560",AES);
				 pOut.println(answer);
				 System.out.println("cliente envió cédula-" + answer + "-continuando.");

				 //se envia la clave
				 answer = cifrar("conTraSeNaS3GuR4",AES);
				 pOut.println(answer);
				 System.out.println("cliente envió contraseña-" + answer + "-continuando.");

				 //se lee el valor que envia el servidor
				 String valor = pIn.readLine();
				 valor = descifrar(valor,AES);
				 System.out.println("cliente recibio valor-" + valor + "-continuando.");

				 //Recibo el valor cifrado con la llave pública del servidor y el HMAC establecido y lo descifro.

				 //Primero descifro el HMAC con la llave pública del servidor.
				 line = pIn.readLine();
				 cifradorRSA.init(Cipher.DECRYPT_MODE,certSer.getPublicKey());
				 byte serverAns1[] = cifradorRSA.doFinal(DatatypeConverter.parseBase64Binary(line));

				 //Luego descifro con la llave secreta y usando HMAC
				 Mac cifradorHMAC = Mac.getInstance(HMAC);
				 cifradorHMAC.init(privateKey);
				 byte be [] = cifradorHMAC.doFinal(DatatypeConverter.parseBase64Binary(valor));

				 //Verifico que el valor sea igual a lo que acabo de descifrar.
				 if(Arrays.equals(serverAns1,be))
				 {
					 System.out.println("Las funciones de Hash correspondientes a los valores coinciden");
					 answer = OK;
				 }
				 else {
					 answer = ERROR;
					 System.out.println(answer);
					 return;
				 }
				 pOut.println(answer);
				 //Termina la conexión.
				 System.out.println("Conexión terminada con "+ answer +".");

			 }
		 }
	}

	@Override
	public void fail() 
	{
		P.perdidas++;
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() 
	{
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() 
	{
		Socket s = null;
		try {
			s = new Socket("localhost", 1234);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}//Esta es la dirección de ejecución del servidor/,"1234"/Este es el puerto que usa el server/);
		BufferedReader buffer = null;
		try {
			buffer = new BufferedReader(new InputStreamReader(s.getInputStream()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		PrintWriter printer = null;
		try {
			printer = new PrintWriter(s.getOutputStream(),true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ClienteSeguro protocolo = new ClienteSeguro();
		try {
			protocolo.procesar(buffer, printer);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
}