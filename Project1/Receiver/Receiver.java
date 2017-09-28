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
 * This Receiver class requires the KeyGen class
 * to generate the Symmetric Key, a Private Key and
 * a Public Key. It also needs IV.byteArray
 *
 * There is also a Sender program to encrypt the
 * ciphertext that this program decrypts.
 *
 * 2017 CS3750, w/ Dr. Weiying Zhu's contributed code
 * Authors: Egor Muscat, Andrew Tovio Roberts
 **/

public class Receiver {

	public Receiver() {
	}

	public static void main(String[] args) throws Exception{


      // The Files
      //   symmetric.key
      //   XPrivate.key
      //   XPublic.key
      // are produced by running
      // the program in KeyGen/KeyGen
      //
      //   IV.byteArray is produced
      //   by Sender

      // #2 symmetric.key and XPublic.key are read from files
			// and generated.
      String KXY = readKXYFromFile("symmetric.key");
	  	PublicKey KXPublic = readPublicKeyFromFile("XPublic.key");

      // #3 Get message file name from user System input
      Scanner in = new Scanner(System.in);
	  	System.out.print("Input the name of the message file (ie message.aescipher) : ");
	  	String cipherTextName = in.next();

      // TESTING: Display the byte array of the msg read from
      //          message.aescipher
      System.out.println("\n");
      System.out.println("Hex Bytes from ciphertext:  ");
      toHexa(aesCipherByte);

      // Read IV from IV.byteArray
      byte[] IV = readBytesFromFile("IV.byteArray");

      // Display IV
      System.out.println("\n");
      System.out.println("IV read from File:");
      toHexa(IV);

      // Read the ciphertext file and decrypt it
			readDecryptAppend(cipherTextName, "message.ds-msg", IV, KXY);

      // Read first 128 bytes from "message.ds-msg" to get
      // the digital signature, ie RSA En[Kx-] (SHA256 (M))
//      byte[] digSig =  readDigSignature("message.ds-msg");
//      System.out.println("\n");
//      System.out.println("Cipher Text of Digital Signature:");
//      toHexa(digSig);










      // The filename of the plaintext is passed to md(),
      // which creates a digital digest(hash) of the message
      // and stored in a byte array hash
//      byte[] hash = md(msg);

      // Output to the console the hash in hex
//	  System.out.println("digit digest (hash value):");
//	  toHexa(hash);

      // Save the hash to a digital digest file
//      saveToFile("message.dd", hash);

      // Encrypt the hash with RSA using the Private Key
      // to produce digital signiture
//      byte[] cipheredHash = encryptRSA(KXPublic,hash);

      // Output to console digital signiture in hex (SHA256 enc(hash) + RSA)
//      System.out.println("Cipher Text of Digital Signiture:");
//	  toHexa(cipheredHash);
//      System.out.println("");

      // Save the digital signiture then the original message to file
//      saveToFile("message.dd-msg",cipheredHash);
//      append("message.dd-msg",aesCipherByte);

      // Create a random initialization vector
      // and load it into a byte array
//      byte[] IV = randomIV();

      // The filename of the digital signiture and the original message
      // ((SHA256 + RSA) + original message) is read and loaded into a byte
      // array
//      byte[] digSigAndMsg = toByteArr("message.dd-msg");

      // AES encryption with padding using the
      // Symmetric key and the Initialization Vector, together with the
      // digital signiture + original message.
      // Result being loaded into a byte array.
//      byte[] aesCipher = decryptAES(KXY,IV,digSigAndMsg);

      // First, the Initialization Vector is set to the top
      // of the encrypted file (It will be exposed to potential
      // attackers, which is the norm), then append the AES-encrypted
      // (digital signiture + original message)
//      saveToFile("message.aescipher",IV);
//      append("message.aescipher",aesCipher);

      // Done.
	}






/***************************************************************/
/*                METHODS SECTION                              */
/***************************************************************/

   /**
    * readDigSignature()
    *
    * returns first 128 bytes from a file
    */
    public static byte[] readDigSignature(String fileName) throws Exception {
        System.out.println("read from " + fileName + "\n");
        InputStream is = null;
        byte[] data = new byte[128];
        try {
          // below true flag tells OutputStream to append
          is = new FileInputStream(fileName);
          is.read(data);
        } catch (IOException e) {
          e.printStackTrace();
        } finally {
           try {
             is.close();
           } catch (IOException e) {
             e.printStackTrace();
           }
           return data;
        }
    }




    /**
     * readDecryptAppend()
     */
    public static void readDecryptAppend(String fileToRead, String fileToWrite, byte[] IV, String KXY) throws Exception {
        File f = new File(fileToRead);
        FileInputStream in = new FileInputStream(f);
        int buff = 16;
        int count = 1;
        byte[] ba = new byte[buff];
        int numberOfBytes;

        try {
            while ((numberOfBytes = in.read(ba)) != -1) {
              if (numberOfBytes == 16) {
                    decryptAES(KXY, IV, ba);
                    System.out.println(count + " read(s) of " + numberOfBytes + " bytes");
                    append(fileToWrite,ba);
                    count++;
                }
                else {
                    in.getChannel().position(in.getChannel().size() - numberOfBytes);
                    byte[] extraBytes = new byte[numberOfBytes];
                    in.read(extraBytes);
                    decryptAES(KXY, IV, extraBytes);
                    System.out.println("read extra " + numberOfBytes + " bytes");
                    append(fileToWrite,extraBytes);
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
   public static byte[] encryptRSA(PublicKey KXPublic, byte[] hash) throws Exception {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      SecureRandom random = new SecureRandom();
    	cipher.init(Cipher.ENCRYPT_MODE, KXPublic, random);
    	return cipher.doFinal(hash);
   }


   /**
    * readBytesFromFile() is used here primarily to read the
    * IV from the IV.bytearray file.
    */
   public static byte[] readBytesFromFile(String fileName) {
      File file = new File(fileName);
      FileInputStream fileInputStream = null;
      byte[] bFile = new byte[(int) file.length()];
      try
      {
        // convert file into array of bytes
        fileInputStream = new FileInputStream(file);
        fileInputStream.read(bFile);
        fileInputStream.close();
      }
      catch (Exception e) {
        e.printStackTrace();
      }

      return bFile;

   }


   /**
    * decryptAES() uses the Initialization Vector (IV) and the
    * symmetric key to decrypt the file containing the digital
    * signature and message text.  It returns a byte array
    * to be written out to file.
    *
    * NOTE: Instead of saving off the remainder bits,
    * we are currently using the PKCS5 Padding option.
    */
   public static byte[] decryptAES(String symmetricKey, byte[] IV, byte[] chunkToDecrypt) throws Exception {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
      cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV));
      return cipher.doFinal(chunkToDecrypt);
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
				Receiver.class.getResourceAsStream(keyFileName);
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
     * readPublicKeyFromFile takes a String representing the filename
     * of the File that contains the private key parameters generated by
     * KeyGen.  It creates and returns the PrivateKey
     */
	public static PublicKey readPublicKeyFromFile(String keyFileName)
			throws IOException {
		InputStream in =
				Receiver.class.getResourceAsStream(keyFileName);
		ObjectInputStream oin =
		   	new ObjectInputStream(new BufferedInputStream(in));
		try {
			  BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    System.out.println("Read from " + keyFileName + ":     modulus = " +
		    		m.toString() + ", exponent = " + e.toString() + "\n");
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		    KeyFactory factory = KeyFactory.getInstance("RSA");
		    PublicKey key = factory.generatePublic(keySpec);
		    return key;
		} catch (Exception e) {
			  throw new RuntimeException("Spurious serialisation error", e);
		} finally {
		    oin.close();
		}
	}
}
