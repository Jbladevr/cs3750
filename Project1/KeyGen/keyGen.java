import java.math.BigInteger;
import java.io.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

public class keyGen 
{
	public static void main(String[] args) throws Exception {
		//Generate a pair of keys
	    	SecureRandom random = new SecureRandom();
	    	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    	generator.initialize(1024, random);  //1024: key size in bits
	    	KeyPair pair = generator.generateKeyPair();
	    	Key kpublic = pair.getPublic();
	    	Key kprivate = pair.getPrivate();

	    	//User input for 16 char symmetric key (work in progress, basic version)
		Scanner input = new Scanner(System.in);
	    	System.out.print("Enter 16 char:");
	    	String kXY = input.next();
	    	input.close();
	   
	    	//get the parameters of the keys: modulus and exponet
	    	KeyFactory factory = KeyFactory.getInstance("RSA");
	    	RSAPublicKeySpec pubKSpec = factory.getKeySpec(kpublic, 
	        RSAPublicKeySpec.class);
	    	RSAPrivateKeySpec privKSpec = factory.getKeySpec(kprivate, 
	        RSAPrivateKeySpec.class);

	    	//save the parameters of the keys to the files, and save symmetric key
	    	saveToFilePair("XPublic.key", pubKSpec.getModulus(), 
	        pubKSpec.getPublicExponent());
	    	saveToFilePair("XPrivate.key", privKSpec.getModulus(), 
	        privKSpec.getPrivateExponent());
	    	saveToFileKXY("symmetric.key",kXY);
	}

	public static void saveToFilePair(String fileName,
	        BigInteger mod, BigInteger exp) throws IOException {
		    
		//this output will prolly go away, its for debuging   
		System.out.println("Write to " + fileName + ": modulus = " + 
			mod.toString() + ", exponent = " + exp.toString() + "\n");

		ObjectOutputStream oout = new ObjectOutputStream(
			new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
		      	oout.writeObject(exp);
		} catch (Exception e) {
		      	throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	//work in progress since we need to save it as 128-bit UTF-8. Or is it done ?
	public static void saveToFileKXY(String fileName,
	        String msg) throws IOException {
		
		//this output will prolly go away, its for debuging   
		System.out.println("Write to " + fileName + ": msg= " + msg + "\n");

		ObjectOutputStream oout = new ObjectOutputStream(
			new BufferedOutputStream(new FileOutputStream(fileName)));

		try {
			oout.writeObject(msg);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}
}

//also we can ask the teacher if we really need to generat Ykeys or we only generate the ones we use in our program.
