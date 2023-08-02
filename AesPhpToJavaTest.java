import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class AesPhpToJavaTest {

    private static final Base64.Encoder ENCODER = Base64.getMimeEncoder();
    private static final Base64.Decoder DECODER = Base64.getMimeDecoder();

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String MAC_ALGORITHM = "HmacSHA256";

    public static void main(String[] args) throws Exception {
        // 암호화할 평문
        String plainText = "123456789";

        // 암복호화에 사용될 비밀키
        String base64EncKey = "X0hFTExPX0FFU19DQkNfIQ";
        byte[] encKeyBytes = DECODER.decode(base64EncKey);

        // 테스트를 위해 사용할 IV
        String base64Iv = "OB3cCNULJkppXtAL5EyhhA==";
        byte[] ivBytes = DECODER.decode(base64Iv);

        // 암호화
        Key secretKey = new SecretKeySpec(encKeyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        // php와 맞춰주기 위해 base64 인코딩
        String base64EncText = new String(ENCODER.encode(encBytes), StandardCharsets.UTF_8);

        // 복호화
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decBytes = cipher.doFinal(encBytes);
        // java에서 생성한 바이트를 그대로 사용 ( base64인코딩 결과를 복호화한게 아님에 주의 )
        String decText = new String(decBytes, StandardCharsets.UTF_8);

        // MAC
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        SecretKeySpec macKey = new SecretKeySpec(encKeyBytes, MAC_ALGORITHM);
        String base64MacSource = base64Iv + base64EncText;

        mac.init(macKey);
        mac.update(base64MacSource.getBytes());
        String hexMac = Hex.encodeHexString(mac.doFinal());

        System.out.println("원문 : " + plainText);
        System.out.println("IV : " + base64Iv);
        System.out.println("암호화 : " + base64EncText);
        System.out.println("복호화 : " + decText);
        System.out.println("MAC 대상 : " + base64MacSource);
        System.out.println("MAC : " + hexMac);
    }
}

/*
실행결과

원문 : 123456789
IV : OB3cCNULJkppXtAL5EyhhA==
암호화 : ddJ+BFDFAINmDyq1WwpgEw==
복호화 : 123456789
MAC 대상 : OB3cCNULJkppXtAL5EyhhA==ddJ+BFDFAINmDyq1WwpgEw==
MAC : 5b4fbb9428877e14719b7016249adcea7dc33dd7d9681ba2352a95d1010f7c70
 */
