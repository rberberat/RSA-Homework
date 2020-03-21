import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

public class RSA {
    private final static SecureRandom SECURE_RANDOM = new SecureRandom();
    private final static String FILE_ROOT_PATH = "Homework/files/";
    private final static String FILE_MESSAGE_ORIGIN = "text.txt";
    private final static String FILE_MESSAGE_ENCODED = "chiffre.txt";
    private final static String FILE_MESSAGE_DECODED = "text-d.txt";
    private final static String FILE_PRIVATE_KEY = "sk.txt";
    private final static String FILE_PUBLIC_KEY = "pk.txt";

    BigInteger phi, n, e, d;

    //
    public static void main(String[] args){
        RSA rsa = new RSA();
//        rsa.generateNewKeyPair();
//        rsa.encodeTextFile();
        rsa.decodeTextFile();
    }

    public void generateNewKeyPair(){
        this.generateNewKeyPair(256);
    }

    // Aufgabe 1, generiert neue sk.txt und pk.txt-Files im Homework/files-Ordner
    public void generateNewKeyPair(int bitlength){
        // 1.a generieren der beiden unterschiedlichen Primzahlen und multiplikation derer.
        this.generateNandPhi(bitlength);
        // 1.b Bestimmen von e und d mithilfe von erweitertem euklidischem Algo.
        this.pickRandomEandD(bitlength);
        // 1.c Schreiben des private Keys.
        writePrivateKeyFile();
        // 1.c Schreiben des public Keys.
        writePublicKeyFile();
    }

    // Aufgabe 2, codiert die text.txt-Datei aus Homework/files-Ordner und schreibt Ergebnis in chiffre.txt
    public void encodeTextFile(){
        // 2 Einlesen von text.txt-Datei
        String file = readFromTextFile(FILE_ROOT_PATH + FILE_MESSAGE_ORIGIN);

        // 2.a Einlessen und parsen von Public Key aus pk.txt
        String publicKey = readFromTextFile(FILE_ROOT_PATH + FILE_PUBLIC_KEY);
        parsePublicKeyString(publicKey);

        // 2.b ASCII-Umwandlung
        char[] charArray = file.toCharArray();

        // 2.c Verschlüsselung der einzelnen Zeichen mithilfe schneller Exponentiation
        List<BigInteger> bigIntegerList = new ArrayList<>();
        for (char character : charArray){
            BigInteger encodedAscii = encode(BigInteger.valueOf(character));
            bigIntegerList.add(encodedAscii);
        }

        // 2.d Umwandlung der codierten Zeichen zu String
        Iterator<BigInteger> iter = bigIntegerList.iterator();
        StringBuilder sb = new StringBuilder();
        while (iter.hasNext()){
            sb.append(iter.next());
            if(iter.hasNext()){
                sb.append(",");
            }
        }

        // 2.d Schreiben des Strings in chiffre.txt
        writeToTextFile(FILE_ROOT_PATH + FILE_MESSAGE_ENCODED, sb.toString());
    }

    // Aufgabe 3, decodiert die chiffre.txt-Datei aus Homework/files-Ordner und schreibt Ergebnis in text-d.txt
    public void decodeTextFile(){
        // 3.a Einlesen von chiffre.txt
        String file = readFromTextFile(FILE_ROOT_PATH + FILE_MESSAGE_ENCODED);
        String[] fileStringArray = file.split(",");

        // 3.b Einlessen und parsen von Private Key aus sk.txt
        String privateKey = readFromTextFile(FILE_ROOT_PATH + FILE_PRIVATE_KEY);
        parsePrivateKeyString(privateKey);

        // 3.c Entschlüsseln der einzelnen Zeichen mithilfe schneller Exponentiation
        List<Character> chars = new ArrayList<>();
        for (String string: fileStringArray) {
            BigInteger bi = new BigInteger(string);
            bi = decode(bi);
            chars.add((char) bi.intValue());
        }

        // 3.d Umwandlung der decodierten Zeichen zu String
        StringBuilder sb = new StringBuilder();
        for (Character aChar : chars) {
            sb.append(aChar.toString());
        }

        // 3.d Schreiben des Strings in text-d.txt
        writeToTextFile(FILE_ROOT_PATH + FILE_MESSAGE_DECODED, sb.toString());
    }

    // 1.a generieren der beiden unterschiedlichen Primzahlen und multiplikation derer.
    private void generateNandPhi(int bitLength){
        BigInteger p, q;
        p = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);

        do {
            q = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);
        } while (p.equals(q));

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);
    }

    // 1.b Bestimmen von e und d mithilfe von erweitertem euklidischem Algo.
    private void pickRandomEandD(int bitLength){
        Map<String, BigInteger> euclidMap;
        do {
            e = new BigInteger(bitLength/2, SECURE_RANDOM);
            euclidMap = euclid(phi, e);
            d = euclidMap.get("y0");
        } while (!euclidMap.get("a").equals(BigInteger.ONE));
    }

    // 1.b Erwiterter euklidischer Algorithmus
    private Map<String, BigInteger> euclid(BigInteger n, BigInteger e){

        BigInteger a, b, x0, x1, y0, y1, q, r;
        a = n;
        b = e;
        x0 = BigInteger.ONE;
        x1 = BigInteger.ZERO;
        y0 = BigInteger.ZERO;
        y1 = BigInteger.ONE;

        do {
            BigInteger[] bi = a.divideAndRemainder(b);
            q = bi[0];
            r = bi[1];

            a = b;
            b = r;

            BigInteger tempx = x1;
            BigInteger tempy = y1;
            x1 = x0.subtract(q.multiply(x1));
            y1 = y0.subtract(q.multiply(y1));
            x0 = tempx;
            y0 = tempy;
        } while (!b.equals(BigInteger.ZERO));

        if (y0.intValue() < 0){
            y0 = y0.add(n);
        }

        Map<String, BigInteger> values = new HashMap<>();
        values.put("a", a);
        values.put("b", b);
        values.put("x0", x0);
        values.put("y0", y0);
        values.put("x1", x1);
        values.put("y1", x0);

        return values;
    }

    // 2.c Algorithmus des schnellen Exponentiation
    private BigInteger fastExponentiation(BigInteger x, BigInteger e, BigInteger m){
        BigInteger i, h, k;

        String[] binaryStringArray = e.toString(2).split("");
        i = BigInteger.valueOf(binaryStringArray.length - 1);
        h = BigInteger.ONE;
        k = x;

        while (i.compareTo(BigInteger.ZERO) >= 0){
            if(binaryStringArray[i.intValue()].equals("1")){
                h = h.multiply(k).mod(m);
            }
            k = k.multiply(k).mod(m);
            i = i.subtract(BigInteger.ONE);
        };
        return h;
    }

    // Helfermethode zum einlesen des Private Keys
    private void parsePrivateKeyString(String sk){
        sk = sk.substring(1, sk.length()-1);
        String[] array = sk.split(",");

        this.n = new BigInteger(array[0]);
        this.d = new BigInteger(array[1]);

    }

    // Helfermethode zum einlesen des Public Keys
    private void parsePublicKeyString(String pk){
        pk = pk.substring(1, pk.length()-1);
        String[] array = pk.split(",");

        this.n = new BigInteger(array[0]);
        this.e = new BigInteger(array[1]);

    }

    // Helfermethode zum schreiben des Private Keys
    private void writePrivateKeyFile(){
        String sk = String.format("(%d,%d)", this.n, this.d);
        String path = FILE_ROOT_PATH + FILE_PRIVATE_KEY;
        writeToTextFile(path, sk);
    }

    // Helfermethode zum schreiben des Public Keys
    private void writePublicKeyFile(){
        String pk = String.format("(%d,%d)", this.n, this.e);
        String path = FILE_ROOT_PATH + FILE_PUBLIC_KEY;
        writeToTextFile(path, pk);
    }

    // Methode zum einlesen von Text-Files
    private String readFromTextFile(String path) {
        try {
            return Files.readString(Paths.get(path));
        } catch (IOException e){
            e.printStackTrace();
        }

        return null;
    }

    // Methode zum schreiben von Text-Files
    private void writeToTextFile(String path, String content) {
        try {
            Path outPath = Paths.get(path);
            Files.writeString(outPath, content);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    // Methode zum "codieren" von BigIntegers
    private BigInteger encode(BigInteger message){
        return this.fastExponentiation(message, e, n);
    }

    // Methode zum "decodieren" von BigIntegers
    private BigInteger decode(BigInteger encrypted){
        return this.fastExponentiation(encrypted, d, n);
    }
}
