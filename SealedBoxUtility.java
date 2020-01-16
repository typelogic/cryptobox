import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import ove.crypto.digest.Blake2b;
import com.iwebpp.crypto.TweetNaclFast;

/**
 * Example how to open sealed boxes in pure java (libsodium sealed boxes
 * according to
 * https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html)
 *
 * Has a dependency on TweetNaclFast and Blake2B, for example
 *
 * https://github.com/alphazero/Blake2b
 * and
 * https://github.com/InstantWebP2P/tweetnacl-java
 *
 */
class SealedBoxUtility
{
    public static final int crypto_box_NONCEBYTES = 24;
    public static final int crypto_box_PUBLICKEYBYTES = 32;
    public static final int crypto_box_MACBYTES = 16;
    public static final int crypto_box_SEALBYTES
        = (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);

    ////////////////////////////////////////////////////////////////////////////
    private static byte[] alicepk = {
        (byte)0x8D, (byte)0xF3, (byte)0x6E, (byte)0xC7, (byte)0xF5, (byte)0x40,
        (byte)0xB9, (byte)0xD2, (byte)0x17, (byte)0x22, (byte)0xDF, (byte)0xD1,
        (byte)0x03, (byte)0x96, (byte)0x8A, (byte)0x24, (byte)0xDE, (byte)0xD4,
        (byte)0x9F, (byte)0x14, (byte)0x59, (byte)0x08, (byte)0xDE, (byte)0xAC,
        (byte)0xF4, (byte)0xA4, (byte)0x9F, (byte)0x99, (byte)0x56, (byte)0x0F,
        (byte)0xA7, (byte)0x09};

    private static byte[] alicesk = {
        (byte)0xF2, (byte)0x4D, (byte)0x41, (byte)0x0D, (byte)0x3C, (byte)0x32,
        (byte)0x7E, (byte)0xB9, (byte)0xB6, (byte)0x13, (byte)0x24, (byte)0xD6,
        (byte)0xB8, (byte)0xCC, (byte)0x5F, (byte)0x80, (byte)0xD9, (byte)0x93,
        (byte)0x2A, (byte)0x1E, (byte)0x1C, (byte)0x56, (byte)0xB3, (byte)0xDB,
        (byte)0x77, (byte)0x67, (byte)0x0B, (byte)0x75, (byte)0x1C, (byte)0xDB,
        (byte)0x7F, (byte)0x4B};

    private static byte[] bobpk = {
        (byte)0x36, (byte)0x3A, (byte)0xF2, (byte)0x62, (byte)0x4E, (byte)0xD7,
        (byte)0x36, (byte)0x97, (byte)0x20, (byte)0x99, (byte)0xD9, (byte)0xAB,
        (byte)0x5C, (byte)0x40, (byte)0x06, (byte)0xEB, (byte)0x09, (byte)0x80,
        (byte)0xBE, (byte)0x6C, (byte)0x53, (byte)0x35, (byte)0xEF, (byte)0xD5,
        (byte)0xBC, (byte)0x2A, (byte)0xF5, (byte)0x3B, (byte)0x7B, (byte)0x16,
        (byte)0xB0, (byte)0x0E};

    private static byte[] bobsk = {
        (byte)0xCB, (byte)0xBD, (byte)0x75, (byte)0xDD, (byte)0xB7, (byte)0xB4,
        (byte)0x79, (byte)0x2B, (byte)0x1C, (byte)0xDF, (byte)0x80, (byte)0xEA,
        (byte)0x95, (byte)0x09, (byte)0xFF, (byte)0x46, (byte)0x5A, (byte)0x6C,
        (byte)0x81, (byte)0x6A, (byte)0x6C, (byte)0xF9, (byte)0x27, (byte)0x8D,
        (byte)0x5C, (byte)0x80, (byte)0x6F, (byte)0xBD, (byte)0xC4, (byte)0xB6,
        (byte)0xE7, (byte)0xC7};

    public static void o_(byte[] msg)
    {
        for (int j = 1; j < msg.length + 1; j++) {
            if (j % 32 == 1 || j == 0) {
                if (j != 0) {
                    System.out.println();
                }
                System.out.format("0%d\t|\t", j / 8);
            }
            System.out.format("%02X", msg[j - 1]);
            if (j % 8 == 0) {
                System.out.print(" ");
            }
        }
        System.out.println();
    }
    ////////////////////////////////////////////////////////////////////////////

    //  libsodium
    //  int crypto_box_seal(unsigned char *c, const unsigned char *m,
    //            unsigned long long mlen, const unsigned char *pk);

    /**
     * Encrypt in  a sealed box
     *
     * @param clearText clear text
     * @param receiverPubKey receiver public key
     * @return encrypted message
     * @throws GeneralSecurityException
     */
    public static byte[] crypto_box_seal(byte[] clearText,
                                         byte[] receiverPubKey)
        throws GeneralSecurityException
    {
        // create ephemeral keypair for sender
        TweetNaclFast.Box.KeyPair ephkeypair = TweetNaclFast.Box.keyPair();
        // create nonce
        byte[] nonce
            = crypto_box_seal_nonce(ephkeypair.getPublicKey(), receiverPubKey);
        TweetNaclFast.Box box
            = new TweetNaclFast.Box(receiverPubKey, ephkeypair.getSecretKey());
        byte[] ciphertext = box.box(clearText, nonce);
        if (ciphertext == null)
            throw new GeneralSecurityException("could not create box");

        byte[] sealedbox
            = new byte[ciphertext.length + crypto_box_PUBLICKEYBYTES];
        byte[] ephpubkey = ephkeypair.getPublicKey();

        for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
            sealedbox[i] = ephpubkey[i];

        for (int i = 0; i < ciphertext.length; i++)
            sealedbox[i + crypto_box_PUBLICKEYBYTES] = ciphertext[i];

        return sealedbox;
    }

    //  libsodium:
    //      int
    //      crypto_box_seal_open(unsigned char *m, const unsigned char *c,
    //                           unsigned long long clen,
    //                           const unsigned char *pk, const unsigned char
    //                           *sk)

    /**
     * Decrypt a sealed box
     *
     * @param c ciphertext
     * @param pk receiver public key
     * @param sk receiver secret key
     * @return decrypted message
     * @throws GeneralSecurityException
     */
    public static byte[] crypto_box_seal_open(byte[] c, byte[] pk, byte[] sk)
        throws GeneralSecurityException
    {
        if (c.length < crypto_box_SEALBYTES)
            throw new IllegalArgumentException("Ciphertext too short");

        byte[] pksender = Arrays.copyOfRange(c, 0, crypto_box_PUBLICKEYBYTES);
        byte[] ciphertextwithmac
            = Arrays.copyOfRange(c, crypto_box_PUBLICKEYBYTES, c.length);
        byte[] nonce = crypto_box_seal_nonce(pksender, pk);

        TweetNaclFast.Box box = new TweetNaclFast.Box(pksender, sk);
        byte[] cleartext = box.open(ciphertextwithmac, nonce);
        if (cleartext == null)
            throw new GeneralSecurityException("could not open box");
        return cleartext;
    }

    /**
     *  hash the combination of senderpk + mypk into nonce using blake2b hash
     * @param senderpk the senders public key
     * @param mypk my own public key
     * @return the nonce computed using Blake2b generic hash
     */
    public static byte[] crypto_box_seal_nonce(byte[] senderpk, byte[] mypk)
    {
        // C source ported from libsodium
        //      crypto_generichash_state st;
        //
        //      crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
        //      crypto_generichash_update(&st, pk1, crypto_box_PUBLICKEYBYTES);
        //      crypto_generichash_update(&st, pk2, crypto_box_PUBLICKEYBYTES);
        //      crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);
        //
        //      return 0;
        final Blake2b blake2b
            = Blake2b.Digest.newInstance(crypto_box_NONCEBYTES);
        blake2b.update(senderpk);
        blake2b.update(mypk);
        byte[] nonce = blake2b.digest();
        if (nonce == null || nonce.length != crypto_box_NONCEBYTES)
            throw new IllegalArgumentException("Blake2b hashing failed");
        return nonce;
    }

    public static void keypairInJava()
    {
        try {
            KeyPairGenerator a = KeyPairGenerator.getInstance("DSA");
            a.initialize(2048);
            java.security.KeyPair pair = a.generateKeyPair();

            java.security.PrivateKey privKey = pair.getPrivate();
            java.security.PublicKey pubKey = pair.getPublic();

            byte[] privkeyBytes = privKey.getEncoded();
            byte[] pubkeyBytes = pubKey.getEncoded();

            System.out.println(privkeyBytes.length);
            System.out.println(pubkeyBytes.length);

            o_(privkeyBytes);
            o_(pubkeyBytes);

        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
    }

    public static void main(String[] args)
    {
        byte[] plaintext = "i protect that which matters most".getBytes();
        try {
            byte[] ciphertext = crypto_box_seal(plaintext, bobpk);
            o_(ciphertext);

            byte[] msgBytes = crypto_box_seal_open(ciphertext, bobpk, bobsk);
            String msg = new String(msgBytes);
            System.out.println(msg);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}
