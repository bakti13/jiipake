import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

public class Exchange {
    private static final BigInteger P = new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16);
    private static final BigInteger Q = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16);
    private static final BigInteger G = new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16);
    private static final String AliceID = "Alice";
    private static final String BobID = "Bob";


    /* Step 1.a: Alice sends g^{x1}, g^{x2}, and Bob sends g^{x3}, g^{x4} */
    public HashMap<String, Object> roundOne(String id) {
        HashMap<String, Object> result = new HashMap();
        /* Generate x1 and x2 */
        BigInteger x1 = new BigInteger(160, new SecureRandom());
        BigInteger x2 = new BigInteger(160, new SecureRandom());

        BigInteger gx1 = G.modPow(x1, P);
        BigInteger gx2 = G.modPow(x2, P);
        BigInteger[] sigX1 = generateZKP(P, Q, G, gx1, x1, id);
        BigInteger[] sigX2 = generateZKP(P, Q, G, gx2, x2, id);
        if (id.equalsIgnoreCase(AliceID)) {
            result.put("gx1", gx1);
            result.put("gx2", gx2);
            result.put("ZKP1", sigX1);
            result.put("ZKP2", sigX2);
//            result.put("x1", x1);
            result.put("x2", x2);
        } else {
            result.put("gx3", gx1);
            result.put("gx4", gx2);
            result.put("ZKP3", sigX1);
            result.put("ZKP4", sigX2);
//            result.put("x3", x1);
            result.put("x4", x2);
        }

        return result;
    }


    /* Step 1.b: Verifies ZKPs
     * Alice verifies Bob's ZKP and also check g^{x4} != 1
     * Bob's verifies Alice ZKP and also check g^{x2} != 1 */
    public boolean cekZKP(BigInteger gx1, BigInteger gx2, BigInteger[] sigX1, BigInteger[] sigX2, String id) {
        return (gx2.equals(BigInteger.ONE) || !verifyZKP(P, Q, G, gx1, sigX1, id) ||
                !verifyZKP(P, Q, G, gx2, sigX2, id));
    }

    /* Step 2.a: Alice sends A and Bob sends B */
    public HashMap<String, Object> roundTwo(BigInteger gx1, BigInteger gx2, BigInteger gx3, BigInteger x1, BigInteger s1, String id) {
        HashMap<String, Object> result = new HashMap();
        BigInteger gX = gx1.multiply(gx2).multiply(gx3).mod(P);
        BigInteger x = gX.modPow(x1.multiply(s1).mod(Q), P);
        BigInteger[] sigXs = generateZKP(P, Q, gX, x, x1.multiply(s1).mod(Q), id);
        if (id.equalsIgnoreCase(AliceID)) {
            result.put("A", x);
            result.put("gA", gX);
            result.put("KP{x2*s}", sigXs);
        } else {
            result.put("B", x);
            result.put("gB", gX);
            result.put("KP{x4*s}", sigXs);
        }
        return result;
    }

    /* Step 2.b: Verifies ZKP *
     ** Alice verifies Bob's ZKP => KP{x4*s}) *
     ** Bob verifies Alice's ZKP => KP{x2*s} */
    public boolean chekZKPs(BigInteger gX, BigInteger x, BigInteger[] sigXs, String id) {
        if (id.equalsIgnoreCase(BobID)) {
            return verifyZKP(P, Q, gX, x, sigXs, AliceID);
        } else {
            return verifyZKP(P, Q, gX, x, sigXs, BobID);
        }
    }

    /* Final Step: Generate Session Key (K) */
    public BigInteger getSessionKeys(BigInteger gx1, BigInteger x1, BigInteger x, BigInteger s1) {
        return getSHA1(gx1.modPow(x1.multiply(s1).negate().mod(Q), P).multiply(x).modPow(x1, P));
    }


    public String toJson(Object obj) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return "";
        }
    }

    public HashMap<String, Object> fromJson(String strJson) {
        HashMap<String, Object> result = new HashMap<>();

        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(strJson, new TypeReference<HashMap<String, Object>>() {
            });
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    public BigInteger[] toArray(Object obj) {
        ArrayList<Object> item = (ArrayList<Object>) obj;
        return item.toArray(new BigInteger[item.size()]);
    }

    public boolean validateKey(String keyAlice, String keyBob) {
        return keyBob.equalsIgnoreCase(keyAlice);
    }



    public BigInteger[] generateZKP(BigInteger p, BigInteger q, BigInteger g,
                                    BigInteger gx, BigInteger x, String signerID) {
        BigInteger[] ZKP = new BigInteger[2];

        /* Generate a random v, and compute g^v */
        BigInteger v = new BigInteger(160, new SecureRandom());
        BigInteger gv = g.modPow(v, p);
        BigInteger h = getSHA1(g, gv, gx, signerID); // h

        ZKP[0] = gv;
        ZKP[1] = v.subtract(x.multiply(h)).mod(q); // r = v-x*h

        return ZKP;
    }

    public boolean verifyZKP(BigInteger p, BigInteger q, BigInteger g, BigInteger gx,
                             BigInteger[] sig, String signerID) {

        /* sig={g^v,r} */
        BigInteger h = getSHA1(g, sig[0], gx, signerID);
        // g^v=g^r * g^x^h
        return gx.compareTo(BigInteger.ZERO) == 1 && // g^x > 0
                gx.compareTo(p.subtract(BigInteger.ONE)) == -1 && // g^x < p-1
                gx.modPow(q, p).compareTo(BigInteger.ONE) == 0 && // g^x^q = 1
                /* Below, I took an straightforward way to compute g^r * g^x^h, which needs 2 exp. Using
                 * a simultaneous computation technique would only need 1 exp.
                 */
                g.modPow(sig[1], p).multiply(gx.modPow(h, p)).mod(p).compareTo(sig[0]) == 0;
    }

    public BigInteger getSHA1(BigInteger g, BigInteger gr, BigInteger gx, String signerID) {

        MessageDigest sha = null;

        try {
            sha = MessageDigest.getInstance("SHA-1");

            /* Note: you should ensure the items in H(...) have clear boundaries.
             * It is simple if the other party knows sizes of g, gr, gx
             * and signerID and hence the boundary is unambiguous. If not, you'd
             * better prepend each item with its byte length, but I've
             * omitted that here.
             */

            sha.update(g.toByteArray());
            sha.update(gr.toByteArray());
            sha.update(gx.toByteArray());
            sha.update(signerID.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert sha != null;
        return new BigInteger(sha.digest());
    }

    public BigInteger getSHA1(BigInteger K) {

        MessageDigest sha = null;

        try {
            sha = MessageDigest.getInstance("SHA-1");
            sha.update(K.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert sha != null;
        return new BigInteger(1, sha.digest()); // 1 for positive int
    }
}
