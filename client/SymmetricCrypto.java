import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class SymmetricCrypto {

    public String encrypt(String data, String SecretKey) throws Exception{
        byte[] SecretHashedKey = createMD5(SecretKey);
        SecretKey secKey = new SecretKeySpec(SecretHashedKey, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secKey);
        
        byte[] newData = cipher.doFinal(data.getBytes());
        byte[] encryptedData = Base64.getEncoder().encode(newData);
        
        return new String(encryptedData);
    }

    public String decrypt(String encryptedData, String SecretKey) throws Exception {
        byte[] SecretHashedKey = createMD5(SecretKey);
        SecretKey secKey = new SecretKeySpec(SecretHashedKey, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secKey);
        
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData.getBytes()));

        return new String(decryptedData);   
    }

    public byte[] createMD5(String key) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(key.getBytes());
        byte byteData[] = md.digest();
        return byteData;
    }
}