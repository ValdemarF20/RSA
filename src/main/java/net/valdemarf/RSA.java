package net.valdemarf;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Encrypts a message and decrypts it again
 */
public class RSA {
    private final BigInteger privateKey; // d
    private final BigInteger publicKey; // e
    private static BigInteger modulus; // n

    // generate an N-bit (roughly) public and private key
    RSA(BigInteger messageNum) {
        // Generate two random prime numbers with given bitLength
        final SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(2048, random);
        BigInteger q = BigInteger.probablePrime(2048, random);
        modulus = p.multiply(q);

        // If the modulus is less than the input, generate a new value
        while(modulus.compareTo(messageNum) < 0 || p.equals(q)) {
            p = p.nextProbablePrime();
            modulus = p.multiply(q);
        }

        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // Totient function - used to calculate the private key
        publicKey = new BigInteger("65537");     // common value in practice = 2^16 + 1
        privateKey = publicKey.modInverse(phi); // e^(-1) % phi
    }

    /**
     * Encrypts a given BigInteger using the formula:
     * message^(e) % n
     * @param message The input message, converted to a BigInteger
     * @return The encrypted BigInteger
     */
    public BigInteger encrypt(BigInteger message) {
        if(message == null) {
            System.out.println("Improper message input");
            return null;
        }
        return message.modPow(publicKey, modulus);
    }

    /**
     * Decrypts an encrypted BigInteger using the formula:
     * encrypted^(d) % n
     * @param encrypted The encrypted BigInteger
     * @return The decrypted BigInteger
     */
    public BigInteger decrypt(BigInteger encrypted) {
        if(encrypted == null) {
            System.out.println("Improper encryption input");
            return null;
        }
        return encrypted.modPow(privateKey, modulus);
    }

    /**
     * Prints information about the most important RSA values
     * @return String containing the information
     */
    public String toString() {
        String s = "";
        s += "public  = " + publicKey + "\n";
        s += "private = " + privateKey + "\n";
        s += "modulus = " + modulus;
        return s;
    }

    /**
     * Main method that runs when the application starts
     * @param args Only one argument which is an input text that will be encrypted and decrypted
     */
    public static void main(String[] args) {
        // Check if args are entered correctly by the user
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();

        // Convert the message to bytes, and then encrypt and decrypt using those bytes
        byte[] bytes = message.getBytes();
        BigInteger messageNum = new BigInteger(bytes);
        RSA key = new RSA(messageNum);
        System.out.println(key);

        BigInteger encrypt = key.encrypt(messageNum);
        BigInteger decrypt = key.decrypt(encrypt);

        // Output
        System.out.println("message = " + message + " -|- message number = " + messageNum);
        System.out.println("encrypted message = " + (new String(encrypt.toByteArray())) + " -|- encrypted number = " + encrypt);
        System.out.println("decrypted message = " + (new String(decrypt.toByteArray())) + " -|- decrypted number = " + decrypt);
    }
}