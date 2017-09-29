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

public class KeyGen 
{
	public KeyGen(){};
	public static void main(String[] args) throws Exception {
		//Generate a pair of keys
	    	SecureRandom random = new SecureRandom();
	    	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    	generator.initialize(1024, random);  //1024: key size in bits
	    	KeyPair pairX = generator.generateKeyPair();
	    	Key kXpublic = pairX.getPublic();
	    	Key kXprivate = pairX.getPrivate();
         KeyPair pairY = generator.generateKeyPair();
	    	Key kYpublic = pairY.getPublic();
	    	Key kYprivate = pairY.getPrivate();

         //User input for 16 char symmetric key (work in progress, basic version)
		    Scanner input = new Scanner(System.in);

            int counter = 0;
            String kXY = "";
            System.out.print("Enter 16 characters: " );

            while(kXY.length() < 16 || kXY.length() > 16) {
                
	            kXY = input.nextLine();
	            if(kXY.length() < 16 || kXY.length() > 16 ) System.out.println("You must input 16 characters for the Key");
            }

            input.close();
	    	//get the parameters of the keys: modulus and exponet
	    	KeyFactory factory = KeyFactory.getInstance("RSA");
	    	RSAPublicKeySpec pubKXSpec = factory.getKeySpec(kXpublic, 
	        RSAPublicKeySpec.class);
	    	RSAPrivateKeySpec privKXSpec = factory.getKeySpec(kXprivate, 
	        RSAPrivateKeySpec.class);
         RSAPublicKeySpec pubKYSpec = factory.getKeySpec(kYpublic, 
	        RSAPublicKeySpec.class);
	    	RSAPrivateKeySpec privKYSpec = factory.getKeySpec(kYprivate, 
	        RSAPrivateKeySpec.class);
           

	    	//save the parameters of the keys to the files, and save symmetric key
	    	saveToFilePair("XPublic.key", pubKXSpec.getModulus(), 
	        pubKXSpec.getPublicExponent());
	    	saveToFilePair("XPrivate.key", privKXSpec.getModulus(), 
	        privKXSpec.getPrivateExponent());
	    	saveToFilePair("YPublic.key", pubKYSpec.getModulus(), 
	        pubKYSpec.getPublicExponent());
	    	saveToFilePair("YPrivate.key", privKYSpec.getModulus(), 
	        privKYSpec.getPrivateExponent());
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
