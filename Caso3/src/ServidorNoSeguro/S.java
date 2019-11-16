package ServidorNoSeguro;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class S {
	public static final String DES = "DES";
	public static final String AES = "AES";
	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String ECIES = "ECIES";
	public static final String RC4 = "RC4";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String HMACSHA384 = "HMACSHA384";
	public static final String HMACSHA512 = "HMACSHA512";
	
	public static byte[] se (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] sd (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] ae (byte[] msg, Key key , String algo) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] ad (byte[] msg, Key key , String algo) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	public static byte[] hdg (byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
			InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	
	public static boolean vi(byte[] msg, Key key, String algo, byte [] hash ) throws Exception
	{
		byte [] nuevo = hdg(msg, key, algo);
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if (nuevo[i] != hash[i]) return false;
		}
		return true;
	}

	public static SecretKey kgg(String algoritmo) 
			throws NoSuchAlgorithmException, NoSuchProviderException	{
		int tamLlave = 0;
		if (algoritmo.equals(DES))
			tamLlave = 64;
		else if (algoritmo.equals(AES))
			tamLlave = 128;
		else if (algoritmo.equals(BLOWFISH))
			tamLlave = 128;
		else if (algoritmo.equals(RC4))
			tamLlave = 128;
		
		if (tamLlave == 0) throw new NoSuchAlgorithmException();
		
		KeyGenerator keyGen;
		SecretKey key;
		keyGen = KeyGenerator.getInstance(algoritmo,"BC");
		keyGen.init(tamLlave);
		key = keyGen.generateKey();
		return key;
	}
		
	public static KeyPair grsa() throws NoSuchAlgorithmException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}	

	public static X509Certificate gc(KeyPair keyPair)
	        throws OperatorCreationException, CertificateException {
	  Calendar endCalendar = Calendar.getInstance();
	  endCalendar.add(Calendar.YEAR, 10);
	  X509v3CertificateBuilder x509v3CertificateBuilder =
	          new X509v3CertificateBuilder(new X500Name("CN=localhost"),
	                  BigInteger.valueOf(1),
	                  Calendar.getInstance().getTime(),
	                  endCalendar.getTime(),
	                  new X500Name("CN=localhost"),
	                  SubjectPublicKeyInfo.getInstance(keyPair.getPublic()
	                          .getEncoded()));
	  ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA")
	          .build(keyPair.getPrivate());
	  X509CertificateHolder x509CertificateHolder =
	          x509v3CertificateBuilder.build(contentSigner);
	  return new JcaX509CertificateConverter().setProvider("BC")
	          .getCertificate(x509CertificateHolder);
	}

}
