package net.valdemarf;

import kotlin.Pair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Encrypts a message and decrypts it again
 */
public class RSA {
    private final BigInteger privatNøgle; // d
    private final BigInteger offentligEksponent = new BigInteger("65537"); // common value (e) in practice = 2^16 + 1
    private static BigInteger modulus; // n
    private final Pair<BigInteger, BigInteger> offentligNøgle; // This variable is not used within the code, but would be used in a real example

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
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // Euler totient function - used to calculate the private key

        offentligNøgle = new Pair<>(offentligEksponent, modulus);
        privatNøgle = offentligEksponent.modInverse(phi); // e^(-1) % phi
    }

    /**
     * Encrypts a given BigInteger using the formula:
     * besked^(e) % n
     * @param besked The input besked, converted to a BigInteger
     * @return The encrypted BigInteger
     */
    public BigInteger encrypt(BigInteger besked) {
        if(besked == null) {
            System.out.println("Improper besked input");
            return null;
        }
        return besked.modPow(offentligEksponent, modulus);
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
        return encrypted.modPow(privatNøgle, modulus);
    }

    /**
     * Prints information about the most important RSA values
     * @return String containing the information
     */
    public String toString() {
        String s = "";
        s += "public  = " + offentligEksponent + "\n\n";
        s += "private = " + privatNøgle + "\n\n";
        s += "modulus = " + modulus;
        return s;
    }

    /**
     * Main method that runs when the application starts
     * @param args Provide no args
     */
    public static void main(String[] args) {
        // Get besked from user
        System.out.println("Besked:");
        Scanner scanner = new Scanner(System.in);
        String besked = scanner.nextLine();
        System.out.println("\n");

        // Check if args are entered correctly by the user
        if(besked.isEmpty() || besked.isBlank()) {
            System.out.println("Kan ikke benytte tom tekst");
            return;
        }

        // Convert the besked to bytes, and then encrypt and decrypt using those bytes
        byte[] bytes = besked.getBytes();
        BigInteger beskedTal = new BigInteger(bytes);
        RSA nøgle = new RSA(beskedTal);
        System.out.println(nøgle);

        BigInteger encrypt = nøgle.encrypt(beskedTal);
        BigInteger decrypt = nøgle.decrypt(encrypt);

        // Output
        System.out.println("\n" + "besked = " + besked + " -|- besked tal = " + beskedTal + "\n");
        System.out.println("Krypteret besked = \n" + (new String(encrypt.toByteArray())) + "\n");
        System.out.println("Krypteret tal = \n" + encrypt + "\n");
        System.out.println("Dekrypteret besked = " + (new String(decrypt.toByteArray())) + " -|- dekrypteret tal = " + decrypt);
    }
}