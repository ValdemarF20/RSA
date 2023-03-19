package net.valdemarf;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Kan kryptere eller dekryptere en besked eller et tal
 */
public class RSA {
    private static BigInteger PRIVAT_NOEGLE; // d
    private static final BigInteger OFFENTLIG_EKSPONENT = new BigInteger("65537"); // Standar værdi for e, beregnes med = 2^16 + 1
    private static BigInteger MODULUS; // n

    // generate an N-bit (roughly) public and private key
    RSA(BigInteger beskedTal, boolean dekryptering) {
        // Generer to primtal med given bit længde
        final SecureRandom tilfaeldig = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(2048, tilfaeldig);
        BigInteger q = BigInteger.probablePrime(2048, tilfaeldig);
        MODULUS = p.multiply(q);

        // Hvis modulus er mindre end input tallet, generer en ny værdi
        while(MODULUS.compareTo(beskedTal) < 0 || p.equals(q)) {
            p = p.nextProbablePrime();
            MODULUS = p.multiply(q);
        }

        if(dekryptering) { // Skal kun brugt privat nøgle til dekryptering
            // Euler totient funktion - brugt til at beregne privat nøgle
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
            PRIVAT_NOEGLE = OFFENTLIG_EKSPONENT.modInverse(phi); // e^(-1) % phi (Euklids algoritme)
        }
    }

    RSA() {} // Brugt til at køre programmet uden at genererer privat nøgle og modulus

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
        return besked.modPow(OFFENTLIG_EKSPONENT, MODULUS);
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
        return krypteret.modPow(PRIVAT_NOEGLE, MODULUS);
    }

    /**
     * Får de vigtigste informationer fra beregningerne
     * @return String der indeholder informationerne
     */
    public String toString() {
        String s = "";
        if(PRIVAT_NOEGLE == null) {
            s += "public  = " + OFFENTLIG_EKSPONENT + "\n\n";
        } else {
            s += "private = " + PRIVAT_NOEGLE + "\n\n";
        }
        s += "modulus = " + MODULUS + "\n\n";
        return s;
    }

    /**
     * Funktion der starter når programmet starter
     * @param args "krypter" eller "dekrypter"
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        List<String> informationer = new ArrayList<>();

        // Enten krypter eller dekrypter
        System.out.println("Valg (krypter eller dekrypter)");
        String valg = scanner.nextLine().toLowerCase();

        // Få besked fra bruger
        BigInteger input = faaInput(scanner);
        if(input == null) {
            return;
        }
        RSA objekt;
        if(valg.equals("krypter")) {
            objekt = genererObjekt(scanner, input, false);
            if(objekt == null) {
                return;
            }

            informationer.addAll(objekt.krypterInput(input));

        } else if(valg.equals("dekrypter")) {
            objekt = genererObjekt(scanner, input, true);
            if(objekt == null) {
                return;
            }
            informationer.addAll(objekt.dekrypterInput(input));
        } else {
            System.out.println("Forkert input");
            return;
        }

        // Output
        System.out.println("\n");
        System.out.println(objekt);
        for (String information : informationer) {
            System.out.println(information);
        }
    }

    /**
     * Funktion brugt til at dekryptere input besked eller tal
     * @param input Input besked eller tal der skal dekrypteres
     * @return En liste af informationer der printes i slutningen af programmet
     */
    public List<String> dekrypterInput(BigInteger input) {
        BigInteger dekrypteret = this.dekrypter(input);

        // Tilføj informationer
        List<String> informationer = new ArrayList<>(3);
        informationer.add(this.toString());
        informationer.add("Dekrypteret besked = " + (new String(dekrypteret.toByteArray())));
        informationer.add("Dekrypteret tal = " + dekrypteret);
        return informationer;
    }

    /**
     * Funktion brugt til at kryptere input besked eller tal
     * @param input Input besked eller tal der skal krypteres
     * @return En liste af informationer der printes i slutningen af programmet
     */
    public List<String> krypterInput(BigInteger input) {
        BigInteger krypteret = this.krypter(input);

        // Tilføj informationer
        List<String> informationer = new ArrayList<>(4);
        informationer.add("\n" + "Input = " + input + "\n");
        informationer.add(this.toString());
        informationer.add("Krypteret besked = \n" + (new String(krypteret.toByteArray())) + "\n");
        informationer.add("Krypteret tal = \n" + krypteret + "\n");
        return informationer;
    }

    /**
     * Funktion brugt til at få input besked eller tal
     * @param scanner Scanner brugt til at skaffe information fra bruger, via output stream
     * @return En tal-værdi for inputtet
     * @throws NumberFormatException Hvis der vælges tal som input, men der ikke skrives et tal efterfølgende
     */
    public static BigInteger faaInput(Scanner scanner) throws NumberFormatException {
        System.out.println("Besked eller tal?");
        String svar = scanner.nextLine().toLowerCase();
        if(!svar.equals("besked") && !svar.equals("tal")) {
            return null;
        }
        System.out.println("Indsæt " + svar + ":");
        String vaerdi = scanner.nextLine();

        BigInteger input;
        if(svar.equals("besked")) {
            input = new BigInteger(vaerdi.getBytes());
        } else {
            input = new BigInteger(vaerdi);
        }
        return input;
    }

    /**
     * Funktion brugt til at genererer et objekt af klassen
     * @param scanner Scanner brugt til at skaffe information fra bruger, via output stream
     * @param input Input besked eller tal der skal krypteres eller dekrypteres
     * @param dekryptering Sandt hvis input skal dekrypteres og falsk hvis det skal krypteres
     * @return Et objekt af klassen
     */
    public static RSA genererObjekt(Scanner scanner, BigInteger input, boolean dekryptering) {
        RSA objekt;
        if(dekryptering) { // Den private nøgle og modulus skal bruges til dekryptering
            System.out.println("Selvvalgt privat nøgle og modulus?");
            String selvvalgt = scanner.nextLine().toLowerCase();
            if(selvvalgt.equals("ja")) {
                System.out.println("Privat nøgle:");
                PRIVAT_NOEGLE = scanner.nextBigInteger();
                System.out.println("Modulus:");
                MODULUS = scanner.nextBigInteger();
                objekt = new RSA();
            } else if(selvvalgt.equals("nej")) {
                objekt = new RSA(input, true);
            } else {
                System.out.println("Forkert input");
                return null;
            }
        } else { // Kun modulus skal bruges til kryptering, og derfor ikke den private nøgle
            System.out.println("Selvvalgt modulus?");
            String selvvalgt = scanner.nextLine().toLowerCase();
            if(selvvalgt.equals("ja")) {
                System.out.println("Modulus:");
                MODULUS = scanner.nextBigInteger();
                objekt = new RSA();
            } else if(selvvalgt.equals("nej")) {
                objekt = new RSA(input, false);
            } else {
                System.out.println("Forkert input");
                return null;
            }
        }
        return objekt;
    }
}