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
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

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

public class SenderTemp {

	public SenderTemp() {
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
	  	String plaintextInput = in.next();

      // The filename of the plaintext is passed to messageDigest(),
      // which creates a digital digest(hash) of the message
      // and stored in a byte array hash
      byte[] hash = messageDigest(plaintextInput);

      // Output to the console the hash in hex
	  	System.out.println("digit digest (hash value):");
	  	toHexa(hash);

      // Save the hash to a digital digest file
      saveToFile("message2.dd", hash);

      // Encrypt the hash with RSA using the Private Key
      // to produce digital signature
      byte[] cipheredHash = encryptRSA(KXPrivate,hash);

      // Output to console digital signature in hex (SHA256 enc(hash) + RSA)
      System.out.println("Cipher Text of Digital Signiture:");
	  	toHexa(cipheredHash);
      System.out.println("");

      // Save the digital signature
      saveToFile("message2.dd2-msg",cipheredHash);


      // The plaintext input is read in 16-byte chunks and
			// is appended to the message2.dd2-msg file.
			System.out.println("appended to message2.dd2-msg: ");
      readPtextAndAppend("message2.dd2-msg", plaintextInput);

      System.out.println("");


      // Create a random initialization vector
      // and load it into a byte array then save it to file
      byte[] IV = randomIV();

			// Print IV to console
      System.out.println();
      System.out.println("Randomly Generated IV:");
      toHexa(IV);
      saveToFile("IV2.byteArray",IV);



      //need a new comment
      readEncryptAppend("message2.dd2-msg","message2.aescipher",IV,KXY);
      System.out.println("appended to message2.aescipher");
      in.close();
      // Done.
	}








/*****************************************************************/
/*                     METHODS SECTION                           */
/*****************************************************************/


	/**
     * readPTextAndAppend reads in 16-byte chunks from a file
		 * and writes out to another file.
     */
	public static void readPtextAndAppend(String fileWrite, String fileRead) throws Exception {
			File f = new File( fileRead );
	    FileInputStream in = new FileInputStream( f );
	    int buff = 16;
	    int count = 1;
			byte[] ba = new byte[buff];
			int numberOfBytes;
			try {
	      while ((numberOfBytes = in.read(ba)) != -1) {
	    	  if (numberOfBytes == 16) {
	    		  System.out.println(count + " read(s) of " + numberOfBytes + " bytes");
						// TESTING: console output of read
						toHexa(ba);

	    		  append(fileWrite,ba);
	    		  count++;
	    	  }
	    	  else {
	    		  in.getChannel().position(in.getChannel().size() - numberOfBytes);
	    		  byte[] extraBytes = new byte[numberOfBytes];
	    		  in.read(extraBytes);
	    		  System.out.println("read extra " + numberOfBytes + " bytes");
						// TESTING: console output of read
						toHexa(ba);

	    		  append(fileWrite,extraBytes);
	    	  }
	       }
	     } catch (IOException e) {
	    	e.printStackTrace();
	   }
	}

	public static void readEncryptAppend(String fileRead, String fileWrite, byte[] IV, String KXY) throws Exception {
			File f = new File(fileRead);
	    FileInputStream in = new FileInputStream(f);
	    int buff = 16;
	    int count = 1;
			byte[] ba = new byte[buff];
			int numberOfBytes;
			try {
	      while ((numberOfBytes = in.read(ba)) != -1) {
	    	  if (numberOfBytes == 16) {
	    		  encryptAES(KXY, IV, ba);
	    		  System.out.println(count + " read(s) of " + numberOfBytes + " bytes");
						// TESTING:  just checking chunk
						toHexa(ba);
						// Create new file if first round
						if(count == 1) {
							saveToFile(fileWrite, ba);
						}	else {
							append(fileWrite, ba);
						}

	    		  count++;
	    	  }
	    	  else {
	    		  in.getChannel().position(in.getChannel().size() - numberOfBytes);
	    		  byte[] extraBytes = new byte[numberOfBytes];
	    		  in.read(extraBytes);
	    		  encryptAES(KXY, IV, extraBytes);
	    		  System.out.println("read extra " + numberOfBytes + " bytes");
						// TESTING:  just checking chunk
						toHexa(extraBytes);
	    		  append(fileWrite,extraBytes);
	    	  }
	       }
	     } catch (IOException e) {
	    	e.printStackTrace();
	   }
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
    *  the beginning of the finished ciphertext message2.aescipher
    *  so that the Decrypt program will be able to use it.
    */
	public static byte[] randomIV(){
      SecureRandom random = new SecureRandom();
      byte[] bytes = new byte[16];
			// Uncomment for Production:  random.nextBytes(bytes);
			// TESTING: for loop to populate IV as static
			for( int i = 0; i < bytes.length; i++ ) {
				bytes[i] = (byte) 1;
			}
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
   public static byte[] encryptAES(String symmetricKey, byte[] IV, byte[] chunkToEncrypt) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
      return cipher.doFinal(chunkToEncrypt);
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
     * append() takes a fileName representing the file to be written to, and
     * a byte array that will be written to that file.
     */
	public static void append(String fileName, byte[] data) throws Exception {
		OutputStream os = null;
		try {
			// below true flag tells OutputStream to append
			os = new FileOutputStream(new File(fileName), true);
			// TESTING: seeing how many times this is called
			System.out.print("           written To " + fileName + " :" );
			toHexa(data);

			os.write(data);
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
		System.out.println("Written to " + fileName + "\n");
		FileOutputStream fos = new FileOutputStream(fileName);
		try {
			fos.write(arr);
		}
		finally {
			fos.close();
		}
	}

    /**
     * Provided by Dr. Weiying Zhu.
     * It takes a String representing a filename, opens that corresponding file
     * and creates a SHA256 hash from the contents of the file.  It returns the
     * file's hash as a byte array.
     */
	public static byte[] messageDigest(String f) throws Exception {
	   BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
	   MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
	   DigestInputStream in = new DigestInputStream(file, messageDigest);
      int BUFFER_SIZE = 32 * 1024;
	   int i;
	   byte[] buffer = new byte[BUFFER_SIZE];
	   do {
	      i = in.read(buffer, 0, BUFFER_SIZE);
	   } while (i == BUFFER_SIZE);
	   messageDigest = in.getMessageDigest();
	   in.close();
	   byte[] hash = messageDigest.digest();
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
