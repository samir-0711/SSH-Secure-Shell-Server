import java.math.BigInteger;
import java.util.Random;
 
public class RSA
{
    public String[] generateKey() {
        BigInteger P;
        BigInteger Q;
        BigInteger N;
        BigInteger PHI;
        BigInteger e;
        BigInteger d;
        int maxLength = 1024;
        String[] key = new String[3];

        P = BigInteger.probablePrime(maxLength, new Random());
        Q = BigInteger.probablePrime(maxLength, new Random());
        N = P.multiply(Q);
        PHI = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(maxLength / 2, new Random());
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);

        key[0] = e.toString();
        key[1] = N.toString();
        key[2] = d.toString();

        return key;
    }
 
    // Encrypting the message
    public byte[] encryptMessage(byte[] message, BigInteger e, BigInteger N)
    {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }
 
    // Decrypting the message
    public byte[] decryptMessage(byte[] message, BigInteger d, BigInteger N)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
    
}