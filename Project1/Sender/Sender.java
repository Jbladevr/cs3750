import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;

public class Sender {
	private static int BUFFER_SIZE = 32 * 1024;
	public Sender() {
	}
	
	public static void main(String[] args) throws Exception{
		String KXY = readKXYFromFile("symmetric.key");
	    PrivateKey KPrivate = readPrivKeyFromFile("XPrivate.key");
	    Scanner in = new Scanner(System.in);
	    System.out.print("Input the name of the message file: ");
	    String msg = in.next();
	    byte[] t = toByteArr(msg);
	    in.close();
	    byte[] hash = md(msg).getBytes();
	    System.out.println("digit digest (hash value):");
	    toHexa(hash);
    	saveToFileSHA256("message.dd", hash);
    	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    	byte[] input = md(msg).getBytes(); 
    	SecureRandom random = new SecureRandom();
    	cipher.init(Cipher.ENCRYPT_MODE, KPrivate, random);
    	byte[] cipherText = cipher.doFinal(input);
    	System.out.println("CipherText:");
	    toHexa(cipherText);
    	System.out.println("");
    	saveToFileRSA("message.dd-msg",cipherText);
    	append("message.dd-msg",t);
    	//////////////////////////////////
    	//AES encryption of message.dd-msg
    	//////////////////////////////////
	}
	
	public static void toHexa(byte [] in) {
		for (int k=0, j=0; k<in.length; k++, j++) {
			System.out.format("%2X ", new Byte(in[k])) ;
		    if (j >= 15) {
		    	System.out.println("");
		        j=-1;
		    }
		}
	}
	
	public static byte[] toByteArr(String file) throws Exception {
		FileInputStream fileInputStream = null;
	    byte[] ba = null;
	    try {
	    	File f = new File(file);
	        ba = new byte[(int) f.length()];
	        //read file into bytes[]
	        fileInputStream = new FileInputStream(f);
	        fileInputStream.read(ba);
	    } catch (IOException e) {
	    	e.printStackTrace();
	    } finally {
	    	if (fileInputStream != null) {
	        try {
	        	fileInputStream.close();
	        } catch (IOException e) {
	        	e.printStackTrace();
	            }
	        }
	    }
	    return ba;
	}
	
	public static void append(String fileName, byte[] data) throws Exception {
		System.out.println("append to " + fileName + "\n");
		OutputStream os = null;
		try {
			// below true flag tells OutputStream to append
			os = new FileOutputStream(new File(fileName), true);
			os.write(data, 0, data.length);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public static void saveToFileRSA(String fileName, byte [] arr) throws Exception {
		System.out.println("Write to " + fileName + "\n");
		FileOutputStream fos = new FileOutputStream(fileName);
		try {
			fos.write(arr);
		}
		finally {
			fos.close();
		}
	}
   public static void saveToFileSHA256(String fileName, byte [] arr) throws Exception {
		System.out.println("Write to " + fileName + "\n");
		FileOutputStream fos = new FileOutputStream(fileName);
		try {
			fos.write(arr);
		}
		finally {
			fos.close();
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
