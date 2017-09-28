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
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * This Sender class requires the KeyGen class
 * to generate the Symmetric Key, a Private Key and
 * a Public Key.
 *
 * There is also a Receiver program to decrypt the
 * ciphertext that this program creates.
 *
 * 2017 CS3750, w/ Dr. Weiying Zhu's contributed code
 * Authors: Egor Muscat, Andrew Tovio Roberts
 **/

public class Sender {

	public Sender() {
	}

	public static void main(String[] args) throws Exception{


      // The Files
      //   symmetric.key
      //   XPrivate.key
      //   XPublic.key
      // are produced by running
      // the program in KeyGen/KeyGen

      // symmetric.key and XPrivate.key are read from files
      String KXY = readKXYFromFile("symmetric.key");
	  	PrivateKey KXPrivate = readPrivKeyFromFile("XPrivate.key");

      // Get message file name from user System input
      Scanner in = new Scanner(System.in);
	  System.out.print("Input the name of the message file: ");
	  String msg = in.next();

	  // The filename of the plaintext is passed to toByteArr()
      // and then read in and returned as
      // a byte array.
      byte[] msgAsByte = toByteArr(msg);
	  in.close();


      // The filename of the plaintext is passed to md(),
      // which creates a digital digest(hash) of the message
      // and stored in a byte array hash
      byte[] hash = md(msg);

      // Output to the console the hash in hex
	  System.out.println("digit digest (hash value):");
	  toHexa(hash);

      // Save the hash to a digital digest file
      saveToFile("message.dd", hash);

      // Encrypt the hash with RSA using the Private Key
      // to produce digital signiture
      byte[] cipheredHash = encryptRSA(KXPrivate,hash);

      // Output to console digital signiture in hex (SHA256 enc(hash) + RSA)
      System.out.println("Cipher Text of Digital Signiture:");
	  toHexa(cipheredHash);
      System.out.println("");

      // Save the digital signiture then the original message to file
      saveToFile("message.dd-msg",cipheredHash);
      append("message.dd-msg",msgAsByte);

      // Create a random initialization vector
      // and load it into a byte array
      byte[] IV = randomIV();

      // The filename of the digital signiture and the original message
      // ((SHA256 + RSA) + original message) is read and loaded into a byte
      // array
      byte[] digSigAndMsg = toByteArr("message.dd-msg");

      // AES encryption with padding using the
      // Symmetric key and the Initialization Vector, together with the
      // digital signiture + original message.
      // Result being loaded into a byte array.
      byte[] aesCipher = encryptAES(KXY,IV,digSigAndMsg);

      // First, the Initialization Vector is set to the top
      // of the encrypted file (It will be exposed to potential
      // attackers, which is the norm), then append the AES-encrypted
      // (digital signiture + original message)
      saveToFile("message.aescipher",IV);
      append("message.aescipher",aesCipher);

      // Done.
	}


   /**
    * This encryptRSA method uses RSA encryption with a Private Key to
    * encrypt the SHA256 hash of the message text.
    */
   public static byte[] encryptRSA(PrivateKey KXPrivate, byte[] hash) throws Exception {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      SecureRandom random = new SecureRandom();
    	cipher.init(Cipher.ENCRYPT_MODE, KXPrivate, random);
    	return cipher.doFinal(hash);
   }


   /**
    *  randomIV() generates an Initialization Vector for
    *  AES encryption, as a SecureRandom that loads byte
    *  by byte into a byte array. The IV is later placed at
    *  the beginning of the finished ciphertext message.aescipher
    *  so that the Decrypt program will be able to use it.
    */
	public static byte[] randomIV(){
      SecureRandom random = new SecureRandom();
      byte[] bytes = new byte[16];
      random.nextBytes(bytes);
      return bytes;
   }

   /**
    * encryptAES() uses the Initialization Vector (IV) and the
    * symmetric key to encrypt the file containing the digital
    * signature and message text.  It returns a byte array
    * to be written out to file.
    *
    * NOTE: Instead of saving off the remainder bits,
    * we are currently using the PKCS5 Padding option.
    */
   public static byte[] encryptAES(String symmetricKey, byte[] IV, byte[] digSigAndMsg) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
      cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV));
      return cipher.doFinal(digSigAndMsg);
   }

   /**
    * toHexa() takes a byte array and outputs it to the console
    */
	public static void toHexa(byte [] in) {
		for (int k=0, j=0; k<in.length; k++, j++) {
			System.out.format("%2X ", new Byte(in[k])) ;
		    if (j >= 15) {
		    	System.out.println("");
		        j=-1;
		    }
		}
	}


    /**
     * toByteArr() takes a String representing the name of a file
     * and opens the File corresponding to that name, using a
     * FileInputStream. It returns a byte array.
     */
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


    /**
     * append() takes a fileName representing the file to be written to, and
     * a byte array that will be written to that file.
     */
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

    /**
     * saveToFile() takes a fileName and a byte array, creates a file with that
     * filename and writes to it.
     */
	public static void saveToFile(String fileName, byte [] arr) throws Exception {
		System.out.println("Write to " + fileName + "\n");
		FileOutputStream fos = new FileOutputStream(fileName);
		try {
			fos.write(arr);
		}
		finally {
			fos.close();
		}
	}


    /**
     * md() stands for message digest. It is provided by Dr. Weiying Zhu.
     * It takes a String representing a filename, opens that corresponding file
     * and creates a SHA256 hash from the contents of the file.  It returns the
     * file's hash as a byte array.
     */
	public static byte[] md(String f) throws Exception {
	   BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
	   MessageDigest md = MessageDigest.getInstance("SHA-256");
	   DigestInputStream in = new DigestInputStream(file, md);
      int BUFFER_SIZE = 32 * 1024;
	   int i;
	   byte[] buffer = new byte[BUFFER_SIZE];
	   do {
	      i = in.read(buffer, 0, BUFFER_SIZE);
	   } while (i == BUFFER_SIZE);
	   md = in.getMessageDigest();
	   in.close();
	   byte[] hash = md.digest();
	   System.out.println("");
	   return hash;
	}

	/**
     * readKXYFromFile() takes a String representing the name
     * of the symmetric key and, prints and returns a String representing
     * the symmetric key.
     */
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

    /**
     * readPrivKeyFromFile takes a String representing the filename
     * of the File that contains the private key parameters generated by
     * KeyGen.  It creates and returns the PrivateKey
     */
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
