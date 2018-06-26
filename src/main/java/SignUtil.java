import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/***
 * for sign with RAS and verify
 */
public class SignUtil {
        public static PrivateKey privateKey(String privateKeyString) throws Exception {
                privateKeyString = privateKeyString.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s+", "");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
                return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        }

        public static PublicKey publicKey(String publicKeyString) throws Exception {
                publicKeyString = publicKeyString.replaceAll("\\n", "")
                                .replace("-----BEGIN PUBLIC KEY-----", "")
                                .replace("-----END PUBLIC KEY-----", "");
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
                return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpecX509);
        }

        public static String sign(String text, PrivateKey privateKey) throws Exception {
                Signature signature = Signature.getInstance("SHA1withRSA", new BouncyCastleProvider());
                signature.initSign(privateKey);
                signature.update(text.getBytes());
                return Base64.getEncoder().encodeToString(signature.sign());
        }

        public static boolean verify(String text, String signed, PublicKey publicKey) throws Exception {
                Signature signature = Signature.getInstance("SHA1WithRSA");
                signature.initVerify(publicKey);
                signature.update(text.getBytes("utf-8"));
                return signature.verify(Base64.getDecoder().decode(signed));
        }
}
