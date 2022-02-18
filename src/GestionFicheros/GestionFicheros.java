package GestionFicheros;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public class GestionFicheros {
    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final String NOM_FICH_CLAVE_PUBLICA = "clavepublica.der";
    private static final String NOM_FICH_CLAVE_PRIVADA = "claveprivada.pkcs8";


    public static boolean escribirClavePublicaRSA(PublicKey clavePublica){
        X509EncodedKeySpec x509EncodedKeySpec = null;
        boolean salir = false;
        try (FileOutputStream fosClavePublica = new FileOutputStream(NOM_FICH_CLAVE_PUBLICA)) {
           x509EncodedKeySpec = new X509EncodedKeySpec(
                    clavePublica.getEncoded(), ALGORITMO_CLAVE_PUBLICA);
            fosClavePublica.write(x509EncodedKeySpec.getEncoded());
            System.out.printf("Clave pública guardada en formato %s en fichero %s:\n%s\n",
                    x509EncodedKeySpec.getFormat(), NOM_FICH_CLAVE_PUBLICA,
                    Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));  // clavePublica.getEncoded() tiene lo mismo);
                    salir = true;
        } catch (IOException e) {
            System.out.println("Error de E/S escribiendo clave pública en fichero");
        }
        return salir;
    }

    public static byte[] leerClavePublicaRSA(String nomFichClave){
        byte[] clavePubCodif = null;
        try(FileInputStream fisClavePub = new FileInputStream(NOM_FICH_CLAVE_PUBLICA)) {
            clavePubCodif = fisClavePub.readAllBytes();
        }catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave pública %s\n.", NOM_FICH_CLAVE_PUBLICA);

        } catch (IOException e) {
            System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.",NOM_FICH_CLAVE_PUBLICA);

        }
        return clavePubCodif;
    }

    public static byte[] leerFichero(String rutaFichero){
        byte[] bytes = null;
        try(FileInputStream fis = new FileInputStream(String.valueOf(Path.of(rutaFichero)))){
            bytes = fis.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.println("El fichero no fué encontrado");
        } catch (IOException e) {
            System.out.println("Fallo al ller el fichero");
        }
        return bytes;
    }

    public static boolean escribirClavePrivadaRSA(PrivateKey clavePrivada){
        boolean salir = false;
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = null;
        try (FileOutputStream fosClavePrivada = new FileOutputStream(NOM_FICH_CLAVE_PRIVADA)) {
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    clavePrivada.getEncoded(), ALGORITMO_CLAVE_PUBLICA);
            fosClavePrivada.write(pkcs8EncodedKeySpec.getEncoded());
            System.out.printf("Clave privada guardada en formato %s en fichero %s:\n%s\n",  // clavePrivada.getEncoded() tiene lo mismo
                    pkcs8EncodedKeySpec.getFormat(), NOM_FICH_CLAVE_PRIVADA,
                    Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));
            salir = true;
        } catch (IOException e) {
            System.out.println("Error de E/S escribiendo clave privada en fichero");

        }
        return salir;
    }


}
