package GeneracionClaveRSA;

import GestionFicheros.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class CriptografiaRSA {
    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final int TAM_CLAVE = 1024;
    public static SecureRandom srand;


    /**
     *
     * @return
     */
    public KeyPair generarParClaves(String nomFichClavePublica, String nomFichClavePrivada){
        KeyPair parClaves = null;
        try{
            srand = SecureRandom.getInstanceStrong();
            KeyPairGenerator genParClaves = KeyPairGenerator.getInstance(ALGORITMO_CLAVE_PUBLICA);
            genParClaves.initialize(TAM_CLAVE, srand);
            parClaves = genParClaves.generateKeyPair();
            GestionFicheros.escribirClavePrivadaRSA(parClaves.getPrivate(), nomFichClavePrivada);
            GestionFicheros.escribirClavePublicaRSA(parClaves.getPublic(), nomFichClavePublica);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No se encontró el algoritmo de generacion de números aleatorios");
        }
    return parClaves;
    }





}
