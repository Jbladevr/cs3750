import java.io.*;
import javax.crypto.CipherOutputStream;
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
 *  *
 *   * This Sender class requires the KeyGen class
 *    * to generate the Symmetric Key, a Private Key and
 *     * a Public Key.
 *      *
 *       * There is also a Receiver program to decrypt the
 *        * ciphertext that this program creates.
 *         *
 *          * 2017 CS3750, w/ Dr. Weiying Zhu's contributed code
 *           * Authors: Egor Muscat, Andrew Tovio Roberts
 *            * */

public class Sender {

	public Sender() {
	}

	public static void main(String[] args) throws Exception {


		// The Files
		//   symmetric.key
		//   XPrivate.key
		//   XPublic.key
		// are produced by running
		// the program in KeyGen/KeyGen

		// symmetric.key and XPrivate.key are read from files
		//   in the Sender directory
		String KXY = readKXYFromFile( "symmetric.key" );
		PrivateKey KXPrivate = readPrivKeyFromFile( "XPrivate.key" );

		// Get message file name (the file to be encrypted)
		//   from user via System input
		Scanner in = new Scanner( System.in );
		System.out.print( "Input the name of the message file: " );
		String fileName = in.next();
		in.close();

		// The filename of the plaintext is passed to messageDigest(),
		//   which creates a digital digest(hash) of the message
		//   and stored in a byte array hash
		byte[] hash = messageDigest( fileName );

		// Output to the console the hash in hex
		System.out.println( "digit digest (hash value):" );
		toHexa(hash);

		// Save the hash to a digital digest file
		saveToFile( "message.dd", hash );

		// Encrypt the hash with RSA using the Private Key
		//   to produce digital signiture
		byte[] cipheredHash = encryptRSA( KXPrivate, hash) ;

		// Output to console digital signiture in hex (SHA256 enc(hash) + RSA)
		System.out.println( "Cipher Text of Digital Signiture:" );
		toHexa( cipheredHash );
		System.out.println( "" );

		// Save the digital signiture to a file
		saveToFile( "message.dd-msg", cipheredHash );
		// Append the original message to digital signature file
		append( "message.dd-msg", fileName );

		// Create a random initialization vector
		//   and load it into a byte array
		byte[] IV = randomIV();
		saveToFile( "IV.byteArray", IV );
		//for debugging
		System.out.println( "IV in Hex:" );
		toHexa( IV );
		System.out.println( "" );

		// Using the symmetric key, encrypt the digital digest + message
		//   and output the encrypted file message.aescipher
		encryptAES( KXY, "message.dd-msg", "message.aescipher", IV );


		// TESTING THE DECYPTION OF AES
		//   decryptAES( KXY, "message.aescipher", "plain.text", IV );

		// Done.
	}


	/*****************************************************************/
	/*                     METHODS SECTION                           */
	/*****************************************************************/


	/**
	 * This encryptRSA method uses RSA encryption with a Private Key to
	 * encrypt the SHA256 hash of the message text.
	 */
	public static byte[] encryptRSA( PrivateKey KXPrivate, byte[] hash ) throws Exception {
		Cipher cipher = Cipher.getInstance( "RSA/ECB/PKCS1Padding" );
		SecureRandom random = new SecureRandom();
		cipher.init( Cipher.ENCRYPT_MODE, KXPrivate, random );
		return cipher.doFinal( hash );
	}


	/**
	 *  randomIV() generates an Initialization Vector for
	 *  AES encryption, as a SecureRandom that loads byte
	 *  by byte into a byte array. The IV is later placed at
	 *  the beginning of the finished ciphertext message.aescipher
	 *  so that the Decrypt program will be able to use it.
	 */
	public static byte[] randomIV() {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[16];

		// TESTING LOOP - loads an IV with 1s
		//  for (int i=0; i< bytes.length ;i++){
		//	  bytes[i] = (byte) 1;
		//  }
		random.nextBytes(bytes);
		return bytes;
	}


	/**
	 *  toHexa() takes a byte array and outputs it to the console
	 */
	public static void toHexa( byte [] in ) {
		for (int k=0, j=0; k < in.length; k++, j++) {
			System.out.format( "%2X ", new Byte(in[k]) );
			if ( j >= 15 ) {
				System.out.println( "" );
				j = -1;
			}
		}
	}


	/**
	 * encryptAES takes the symmetric key, the name of a file to encrypt,
	 *   an output file name to write to and an Initialization Vector
	 *   as a byte array.
	 *
	 *   It calls aesCrypt which, performs the encryption and writes out to
	 *   the output file.
	 */
	public static  void encryptAES( String key, String inputFile, String outputFile, byte[] IV )
			throws Exception {
		aesCrypt( Cipher.ENCRYPT_MODE, key, inputFile, outputFile, IV );
	}


	/**
	 * decryptAES is for testing in the Sender class
	 */
	// public static  void decryptAES(String key, String inputFile, String outputFile,byte[] IV)
	// 		throws Exception {
	//	aesCrypt(Cipher.DECRYPT_MODE, key, inputFile, outputFile,IV);
	// }


	/**
	 *  aesCrypt takes an int that represents the cipherMode, the symmettric
	 *    key, the input file's name, the output file's name, and the
	 *    Initialization Vector as a byte array.
	 *
	 *    It reads in the file to encrypt/decrypt in multiples of 16 bytes and
	 *    writes it out in the same multiples.  Thus it can process files
	 *    of an arbitrary size.
	 */
	public static void aesCrypt( int cipherMode, String key, String inputFile,
		String outputFile, byte[] IV ) throws Exception {
		SecretKeySpec secretKey = new SecretKeySpec( key.getBytes("UTF-8"), "AES" );
        Cipher cipher = Cipher.getInstance( "AES/CFB/NoPadding", "SunJCE" );
        cipher.init( cipherMode, secretKey, new IvParameterSpec( IV ) );
        FileInputStream inputStream = new FileInputStream( inputFile );
        FileOutputStream fileout = new FileOutputStream( outputFile );
        CipherOutputStream out = new CipherOutputStream( fileout , cipher );
		try {
            byte[] buffer = new byte[ 16*1024 ];
						int count;
            while ( ( count = inputStream.read( buffer ) ) > 0) {
                out.write( buffer, 0, count );
            }
        } catch ( IOException e ) {
            e.printStackTrace();
        }
        finally {
					out.close();
					inputStream.close();
				}
    }

	/**
	 * Append reads from an input file and writes to an output file.
	 */
	public static void append( String outputFile, String inputFile ) throws Exception {
		System.out.println( "append to " + outputFile + "\n" );
		FileInputStream inputStream = new FileInputStream( inputFile );
		OutputStream outputStream = new FileOutputStream( new File(outputFile), true );
		try {
			byte[] buffer = new byte[ 16*1024 ];
			int count;
			while ( ( count = inputStream.read( buffer ) ) > 0) {
				outputStream.write( buffer, 0, count );
			}
		} catch ( IOException e ) {
			e.printStackTrace();
		} finally {
			try {
				outputStream.close();
				inputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * saveToFile() takes a fileName and a byte array, creates a file with that
	 * filename and writes to it.
	 */
	public static void saveToFile( String fileName, byte [] arr ) throws Exception {
		System.out.println( "Write to " + fileName + "\n" );
		FileOutputStream fos = new FileOutputStream( fileName );
		try {
			fos.write( arr );
		}
		finally {
			fos.close();
		}
	}


	/**
	 * messageDigest() is provided by Dr. Weiying Zhu.
	 *   It takes a String representing a filename, opens that corresponding file
	 *   and creates a SHA256 hash from the contents of the file.  It returns the
	 *   file's hash as a byte array.
	 */
	public static byte[] messageDigest( String f ) throws Exception {
		BufferedInputStream file = new BufferedInputStream( new FileInputStream(f) );
		MessageDigest messageDigest = MessageDigest.getInstance( "SHA-256" );
		DigestInputStream in = new DigestInputStream( file, messageDigest );
		int BUFFER_SIZE = 32 * 1024;
		int i;
		byte[] buffer = new byte[ BUFFER_SIZE ];
		do {
			i = in.read( buffer, 0, BUFFER_SIZE );
		} while ( i == BUFFER_SIZE );
		messageDigest = in.getMessageDigest();
		in.close();
		byte[] hash = messageDigest.digest();
		System.out.println( "" );
		return hash;
	}

	/**
	 * readKXYFromFile() takes a String representing the name
	 *   of the symmetric key and, prints and returns a String representing
	 *   the symmetric key.
	 */
	public static String readKXYFromFile( String keyFileName )
			throws IOException {
		InputStream in =
				Sender.class.getResourceAsStream( keyFileName );
		ObjectInputStream oin =
				new ObjectInputStream( new BufferedInputStream( in ) );
		try {
			String m = ( String ) oin.readObject();
			System.out.println( "Read from " + keyFileName + ": msg= " +
					m.toString()  + "\n" );
			String key = m.toString();
			return key;
		} catch ( Exception e ) {
			throw new RuntimeException( "Spurious serialisation error", e );
		} finally {
			oin.close();
		}
	}

	/**
	 * readPrivKeyFromFile takes a String representing the filename
	 *   of the File that contains the private key parameters generated by
	 *   KeyGen.  It creates and returns the PrivateKey
	 */
	public static PrivateKey readPrivKeyFromFile( String keyFileName )
			throws IOException {
		InputStream in =
				Sender.class.getResourceAsStream( keyFileName );
		ObjectInputStream oin =
				new ObjectInputStream( new BufferedInputStream( in ) );
		try {
			BigInteger m = ( BigInteger ) oin.readObject();
			BigInteger e = ( BigInteger ) oin.readObject();
			System.out.println( "Read from " + keyFileName + ": modulus = " +
					m.toString() + ", exponent = " + e.toString() + "\n" );
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec( m, e );
			KeyFactory factory = KeyFactory.getInstance( "RSA" );
			PrivateKey key = factory.generatePrivate( keySpec );
			return key;
		} catch ( Exception e ) {
			throw new RuntimeException( "Spurious serialisation error", e );
		} finally {
			oin.close();
		}
	}
}
