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

    BigInteger phi, n, e, d;


    public static void main(String[] args){
        RSA rsa = new RSA();
        rsa.generateNewKeyPair();
        rsa.encodeTextFile();
        rsa.decodeTextFile();
    }

    public void generateNewKeyPair(){
        this.generateNewKeyPair(256);
    }

    public void generateNewKeyPair(int bitlength){
        this.generateNandPhi(bitlength);
        this.pickRandomEandD(bitlength);
        writePrivateKeyFile();
        writePublicKeyFile();
    }

    public void encodeTextFile(){
        String file = readFromTextFile(FILE_ROOT_PATH + "text.txt");
        char[] charArray = file.toCharArray();
        String publicKey = readFromTextFile(FILE_ROOT_PATH + "pk.txt");
        List<BigInteger> bigIntegerList = new ArrayList<>();

        parsePublicKeyString(publicKey);

        for (char character : charArray){
            BigInteger encodedAscii = encode(BigInteger.valueOf(character));
            bigIntegerList.add(encodedAscii);
        }

        Iterator<BigInteger> iter = bigIntegerList.iterator();
        StringBuilder sb = new StringBuilder();
        while (iter.hasNext()){
            sb.append(iter.next());
            if(iter.hasNext()){
                sb.append(",");
            }
        }

        writeToFile(FILE_ROOT_PATH + "chiffre1.txt", sb.toString());
    }

    public void decodeTextFile(){
        String file = readFromTextFile(FILE_ROOT_PATH + "chiffre1.txt");
        String privateKey = readFromTextFile(FILE_ROOT_PATH + "sk.txt");
        parsePrivateKeyString(privateKey);

        String[] stringArray = file.split(",");
        List<Character> chars = new ArrayList<>();
        for (String string: stringArray) {
            BigInteger bi = new BigInteger(string);
            bi = decode(bi);
            chars.add((char) bi.intValue());
        }

        StringBuilder sb = new StringBuilder();
        Iterator<Character> iter = chars.iterator();
        while(iter.hasNext()){
            sb.append(iter.next().toString());
        }

        writeToFile(FILE_ROOT_PATH + "test-d.txt", sb.toString());
    }

    private void generateNandPhi(int bitLength){
        BigInteger p, q;
        p = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);

        do {
            q = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);
        } while (p.equals(q));

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);
    }

    private void pickRandomEandD(int bitLength){
        Map<String, BigInteger> euclidMap;
        do {
            e = new BigInteger(bitLength/2, SECURE_RANDOM);
            euclidMap = euclid(phi, e);
            d = euclidMap.get("y0");
        } while (!euclidMap.get("a").equals(BigInteger.ONE));
    }

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

    private BigInteger encode(BigInteger message){
        return message.modPow(e, n);
    }

    private BigInteger decode(BigInteger encrypted){
        return encrypted.modPow(d, n);
    }

    private void parsePrivateKeyString(String sk){
        sk = sk.substring(1, sk.length()-1);
        String[] array = sk.split(",");

        this.n = new BigInteger(array[0]);
        this.d = new BigInteger(array[1]);

    }

    private void parsePublicKeyString(String pk){
        pk = pk.substring(1, pk.length()-1);
        String[] array = pk.split(",");

        this.n = new BigInteger(array[0]);
        this.e = new BigInteger(array[1]);

    }

    private String readFromTextFile(String path) {
        try {
            return Files.readString(Paths.get(path));
        } catch (IOException e){
            e.printStackTrace();
        }

        return null;
    }

    private void writePrivateKeyFile(){
        String sk = String.format("(%d,%d)", this.n, this.d);
        String path = FILE_ROOT_PATH + "sk.txt";
        writeToFile(path, sk);
    }

    private void writePublicKeyFile(){
        String pk = String.format("(%d,%d)", this.n, this.e);
        String path = FILE_ROOT_PATH + "pk.txt";
        writeToFile(path, pk);
    }

    private void writeToFile(String path, String content) {
        try {
            Path outPath = Paths.get(path);
            Files.writeString(outPath, content);
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}
