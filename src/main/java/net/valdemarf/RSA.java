package net.valdemarf;

import kotlin.Pair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Encrypts a message and decrypts it again
 */
public class RSA {
    private static BigInteger privatNøgle; // d
    private final BigInteger offentligEksponent = new BigInteger("65537"); // common value (e) in practice = 2^16 + 1
    private static BigInteger modulus; // n
    private Pair<BigInteger, BigInteger> offentligNøgle; // This variable is not used within the code, but would be used in a real example

    // generate an N-bit (roughly) public and private key
    RSA(BigInteger beskedTal) {
        // Generate two random prime numbers with given bitLength
        final SecureRandom tilfældig = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(2048, tilfældig);
        BigInteger q = BigInteger.probablePrime(2048, tilfældig);
        modulus = p.multiply(q);
        if(beskedTal.equals(BigInteger.ONE.negate())) {
            beskedTal = modulus.subtract(BigInteger.ONE);
        }

        // If the modulus is less than the input, generate a new value
        while(modulus.compareTo(beskedTal) < 0 || p.equals(q)) {
            p = p.nextProbablePrime();
            modulus = p.multiply(q);
        }
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // Euler totient function - used to calculate the private key

        offentligNøgle = new Pair<>(offentligEksponent, modulus);
        privatNøgle = offentligEksponent.modInverse(phi); // e^(-1) % phi
    }

    RSA(BigInteger privatNøgle, BigInteger modulus) {}

    /**
     * Krypterer et tal ved brug af følgende formel:
     * besked^(e) % n
     * @param besked Input beskeden, lavet til en BigInteger
     * @return Det krypterede tal
     */
    public BigInteger krypter(BigInteger besked) {
        if(besked == null) {
            System.out.println("Forkert besked input");
            return null;
        }
        return besked.modPow(offentligEksponent, modulus);
    }

    /**
     * Dekrypterer et tal ved brug af følgende formel:
     * krypteret^(d) % n
     * @param krypteret Det krypterede tal
     * @return Det dekrypterede tal
     */
    public BigInteger dekrypter(BigInteger krypteret) {
        if(krypteret == null) {
            System.out.println("Forkert kryptering input");
            return null;
        }
        return krypteret.modPow(privatNøgle, modulus);
    }

    /**
     * Får de vigtigste informationer fra beregningerne
     * @return String der indeholder informationerne
     */
    public String toString() {
        String s = "";
        s += "public  = " + offentligEksponent + "\n\n";
        s += "private = " + privatNøgle + "\n\n";
        s += "modulus = " + modulus + "\n\n";
        return s;
    }

    /**
     * Funktion der starter når programmet starter
     * @param args "krypter" eller "dekrypter"
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        List<String> informationer = new ArrayList<>();
        System.out.println("Valg (krypter eller dekrypter)");
        String valg = scanner.nextLine().toLowerCase();

        if(valg.equals("krypter")) {
            // Få besked fra bruger
            System.out.println("Besked:");
            String besked = scanner.nextLine();

            // Tjek om beskeden er gyldig
            if(besked.isEmpty() || besked.isBlank()) {
                System.out.println("Kan ikke benytte tom tekst");
                return;
            }

            // Konverter beskeden til bytes, og krypter ved brug af disse
            byte[] bytes = besked.getBytes();
            BigInteger beskedTal = new BigInteger(bytes);
            RSA nøgle = new RSA(beskedTal);
            informationer.addAll(nøgle.krypterInput(besked, beskedTal));

        } else if(valg.equals("dekrypter")) {
            System.out.println("Selvvagt nøgle og modulus?");
            String selvvagt = scanner.nextLine().toLowerCase();
            RSA nøgle;
            if(selvvagt.equals("ja")) {
                System.out.println("Nøgle:");
                privatNøgle = scanner.nextBigInteger();
                System.out.println("Modulus:");
                modulus = scanner.nextBigInteger();
                nøgle = new RSA(privatNøgle, modulus);
            } else {
                nøgle = new RSA(BigInteger.ONE.negate());
            }
            informationer.addAll(nøgle.dekrypterInput(scanner));
        }

        // Output
        System.out.println("\n");
        for (String information : informationer) {
            System.out.println(information);
        }
    }

    public List<String> dekrypterInput(Scanner scanner) {
        String ignorer = scanner.nextLine().toLowerCase(); // Scanner kan ikke se den tidligere nye linje og skal derfor opdateres
        System.out.println("Besked eller tal?");
        String svar = scanner.nextLine().toLowerCase();

        System.out.println("Indsæt værdi:");
        String værdi = scanner.nextLine().toLowerCase();

        BigInteger krypteretInput;
        if(svar.equals("besked")) {
            byte[] bytes = værdi.getBytes();
            krypteretInput = new BigInteger(bytes);
        } else if(svar.equals("tal")) {
            krypteretInput = new BigInteger(værdi);
        } else {
            System.out.println("Forkert input");
            return null;
        }
        BigInteger dekrypteret = this.dekrypter(krypteretInput);

        // Tilføj informationer
        List<String> informationer = new ArrayList<>(3);
        informationer.add(this.toString());
        informationer.add("Dekrypteret besked = " + (new String(dekrypteret.toByteArray())));
        informationer.add("Dekrypteret tal = " + dekrypteret);
        return informationer;
    }

    public List<String> krypterInput(String besked, BigInteger beskedTal) {
        BigInteger krypteret = this.krypter(beskedTal);

        // Tilføj informationer
        List<String> informationer = new ArrayList<>(4);
        informationer.add("\n" + "besked = " + besked + " -|- besked tal = " + beskedTal + "\n");
        informationer.add(this.toString());
        informationer.add("Krypteret besked = \n" + (new String(krypteret.toByteArray())) + "\n");
        informationer.add("Krypteret tal = \n" + krypteret + "\n");
        return informationer;
    }
}