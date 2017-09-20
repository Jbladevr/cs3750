import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Sender {
	private static int BUFFER_SIZE = 32 * 1024;
	public Sender() {
	}
	
	public static void main(String[] args) throws Exception{
		String KXY = readKXYFromFile("symmetric.key");
	    PrivateKey KPrivate = readPrivKeyFromFile("XPrivate.key");
	    Scanner input = new Scanner(System.in);
	    System.out.print("Input the name of the message file: ");
	    String msg = input.next(); //can be NOT a text message does the string work in that case ?
    	input.close();
    	saveToFileSHA256("message.dd", md(msg)); // need to change to only hexadecimal bytes
	}
	public static void saveToFileSHA256(String fileName,String code) throws IOException {
		    
		//this output will prolly go away, its for debuging   
		System.out.println("Write to " + fileName + ": hashCode = " + 
			code.toString() + "\n");

		ObjectOutputStream oout = new ObjectOutputStream(
			new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(code);
		} catch (Exception e) {
		      	throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	public static String md(String f) throws Exception {
	    BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    DigestInputStream in = new DigestInputStream(file, md);
	    int i;
	    byte[] buffer = new byte[BUFFER_SIZE];
	    do {
	      i = in.read(buffer, 0, BUFFER_SIZE);
	    } while (i == BUFFER_SIZE);
	    md = in.getMessageDigest();
	    in.close();

	    byte[] hash = md.digest();

	    System.out.println("digit digest (hash value):");
	    for (int k=0, j=0; k<hash.length; k++, j++) {
	      System.out.format("%2X ", new Byte(hash[k])) ;
	      if (j >= 15) {
	        System.out.println("");
	        j=-1;
	      }
	    }
	    System.out.println("");    

	    return new String(hash);
	  }
	//needs to be changed from string to and OBJECT?
	public static String readKXYFromFile(String keyFileName) 
		      throws IOException {

		    InputStream in = 
		        Sender.class.getResourceAsStream(keyFileName);
		    ObjectInputStream oin =
		        new ObjectInputStream(new BufferedInputStream(in));

		    try {
		      String m = (String) oin.readObject();

		      System.out.println("Read from " + keyFileName + ": msg= " + 
		          m.toString()  + "\n");

		      String key = m.toString();

		      return key;
		    } catch (Exception e) {
		      throw new RuntimeException("Spurious serialisation error", e);
		    } finally {
		      oin.close();
		    }
		  }


		  //read key parameters from a file and generate the private key 
		  public static PrivateKey readPrivKeyFromFile(String keyFileName) 
		      throws IOException {

		    InputStream in = 
		    		Sender.class.getResourceAsStream(keyFileName);
		    ObjectInputStream oin =
		        new ObjectInputStream(new BufferedInputStream(in));

		    try {
		      BigInteger m = (BigInteger) oin.readObject();
		      BigInteger e = (BigInteger) oin.readObject();

		      System.out.println("Read from " + keyFileName + ": modulus = " + 
		          m.toString() + ", exponent = " + e.toString() + "\n");

		      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		      KeyFactory factory = KeyFactory.getInstance("RSA");
		      PrivateKey key = factory.generatePrivate(keySpec);

		      return key;
		    } catch (Exception e) {
		      throw new RuntimeException("Spurious serialisation error", e);
		    } finally {
		      oin.close();
		    }
		  }
}
