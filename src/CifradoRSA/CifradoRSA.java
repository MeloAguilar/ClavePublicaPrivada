package CifradoRSA;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import GestionFicheros.*;




public class CifradoRSA {

    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final String FICH_CLAVE_PUB = ".der";



    /**
     *
     * @param nomFichClave
     * @param rutaFichero
     */
    public void encriptarFichero(String nomFichClave, String rutaFichero) {

        byte[] clavePubCodif = GestionFicheros.leerClavePublicaRSA("C:\\Users\\caguilar.INFO2\\IdeaProjects\\ClavePublicaPrivada\\src\\GeneracionClaveRSA\\Claves\\"+nomFichClave+FICH_CLAVE_PUB);

        KeyFactory factory;
        try{
            factory = KeyFactory.getInstance(ALGORITMO_CLAVE_PUBLICA);
            X509EncodedKeySpec pKeySpec = new X509EncodedKeySpec(clavePubCodif);
            PublicKey clavePublica = factory.generatePublic(pKeySpec);

            byte[] mensajeClaro = GestionFicheros.leerFichero(rutaFichero);

            Cipher cifrado = getPublicCipher(clavePublica);
            byte[] mensajeCifrado = cifrado.doFinal(mensajeClaro);
            System.out.printf("Fichero cifrado codificado en base 64 como texto:\n%s\n",
                    Base64.getEncoder().encodeToString(mensajeCifrado).replaceAll("(.{76})", "$1\n"));

            GestionFicheros.escribirFichero(rutaFichero, ".encrypt", cifrado);

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


    /**
     *
     * @param nomFichClave
     * @param rutaFichero
     */
    public void desencriptarFichero(String nomFichClave, String rutaFichero){
        byte[] clavePrivCodificada = GestionFicheros.leerClavePrivadaRSA(nomFichClave);

        KeyFactory factory;
        try{
            factory = KeyFactory.getInstance(ALGORITMO_CLAVE_PUBLICA);
            PKCS8EncodedKeySpec pKSpec = new PKCS8EncodedKeySpec(clavePrivCodificada);
            PrivateKey clavePrivada = factory.generatePrivate(pKSpec);

            Cipher cifrado = getPrivateCipher(clavePrivada);
            byte[] fichDescifrado = cifrado.doFinal();

            GestionFicheros.escribirFichero(rutaFichero, ".desencrypt", cifrado);

            System.out.printf("Texto descifrado:\n%s\n", new String(fichDescifrado, "UTF-8"));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe algoritmo");
        } catch (InvalidKeySpecException e) {
            System.out.println("Clave publica inválida");
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            System.out.println("No se puede obtener el valor en Base64");
        } catch (BadPaddingException e) {
            System.out.println("No tiene padding");
        }
    }


    /**
     *
     * @param clavePrivada
     * @return
     */
    private Cipher getPrivateCipher(PrivateKey clavePrivada){
        Cipher cifrado = null;
        try{
            cifrado = Cipher.getInstance(ALGORITMO_CLAVE_PUBLICA);
            cifrado.init(Cipher.DECRYPT_MODE, clavePrivada);
        } catch (NoSuchPaddingException e) {
            System.out.println("No existe padding");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("El algoritmo elegido no existe");
        } catch (InvalidKeyException e) {
            System.out.println("La clave pública no es válida para este fichero");
        }
        return cifrado;
    }

    /**
     *
     * @param clavePublica
     * @return
     */
    private Cipher getPublicCipher(PublicKey clavePublica){
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
