import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Main {
    private final static SecureRandom SECURE_RANDOM = new SecureRandom();
    BigInteger phi, n, e, d;

    public static void main(String[] args) {
        Main m = new Main();
        int bitlength = 256;
        m.generateN(bitlength);
        m.pickRandomEandD(bitlength);

        System.out.println(String.format("N: %d", m.n));
        System.out.println(String.format("Phi: %d", m.phi));
        System.out.println(String.format("E: %d", m.e));
        System.out.println(String.format("D: %d", m.d));

        BigInteger randomMessage = new BigInteger(16, SECURE_RANDOM);

        System.out.println(String.format("Message: %d", randomMessage));

        BigInteger encrypted = m.encodeFile(randomMessage);

        System.out.println(String.format("Encrypted Message: %d", encrypted));

        BigInteger decrypted = m.decodeFile(encrypted);

        System.out.println(String.format("Decrypted Message: %d", decrypted));
        System.out.println(decrypted.equals(randomMessage));
    }

    public void generateN(int bitLength){
        BigInteger p, q;
        p = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);

        do {
            q = BigInteger.probablePrime(bitLength/2 , SECURE_RANDOM);
        } while (p.equals(q));

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);
    }

    public void pickRandomEandD(int bitLength){
        Map<String, BigInteger> euclidMap;
        do {
            e = new BigInteger(bitLength/2, SECURE_RANDOM);
            euclidMap = euclid(phi, e);
            d = euclidMap.get("y0");
        } while (!euclidMap.get("a").equals(BigInteger.ONE));
    }

    public Map<String, BigInteger> euclid(BigInteger n, BigInteger e){

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

    public void generatePrivKey(){}

    public void generatePubKey(){}

    public BigInteger encodeFile(BigInteger message){
        return message.modPow(e, n);
    }

    public BigInteger decodeFile(BigInteger encryptedMessage){
        return encryptedMessage.modPow(d, n);
    }
}
