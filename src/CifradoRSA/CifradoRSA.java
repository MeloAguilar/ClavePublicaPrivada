package CifradoRSA;

import GestionFicheros.GestionFicheros;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CifradoRSA {

    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final String FICH_CLAVE_PUB = "clavepublica.der";

    public void encriptarFichero(String nomFich, String rutaFichero) {

        byte[] clavePubCodif = GestionFicheros.leerClavePublicaRSA(nomFich);

        KeyFactory factory;
        try{
            factory = KeyFactory.getInstance(ALGORITMO_CLAVE_PUBLICA);
            X509EncodedKeySpec pKeySpec = new X509EncodedKeySpec(clavePubCodif);
            PublicKey clavePublica = factory.generatePublic(pKeySpec);

            byte[] mensajeClaro = GestionFicheros.leerFichero(rutaFichero);

            byte[] mensajeCifrado = getCipher(clavePublica).doFinal(mensajeClaro);

            System.out.printf("Texto cifrado codificado en base 64 como texto:\n%s\n",
                    Base64.getEncoder().encodeToString(mensajeCifrado).replaceAll("(.{76})", "$1\n"));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe el algoritmo");
        } catch (InvalidKeySpecException e) {
            System.out.println("Las especificaciones de la clave publica no son exactas");
        } catch (IllegalBlockSizeException e) {
            System.out.println("Numero ilegal de bloques");
        } catch (BadPaddingException e) {
            System.out.println("Problemas con el padding");
        }


    }

    private Cipher getCipher(PublicKey clavePublica){
        Cipher cifrado = null;
        try{
            cifrado = Cipher.getInstance(ALGORITMO_CLAVE_PUBLICA);
            cifrado.init(Cipher.ENCRYPT_MODE, clavePublica);
        } catch (NoSuchPaddingException e) {
            System.out.println("No existe padding");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("El algoritmo de encriptacion no existe");
        } catch (InvalidKeyException e) {
            System.out.println("clave no válida");
        }
        return cifrado;
    }
}
