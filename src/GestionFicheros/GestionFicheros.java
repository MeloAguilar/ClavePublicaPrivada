package GestionFicheros;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public class GestionFicheros {


    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final String NOM_FICH_CLAVE_PUBLICA = ".der";
    private static final String NOM_FICH_CLAVE_PRIVADA = ".pkcs8";


    private static String generarRuta(String nomFichClave, int accion) {
        StringBuilder stb = new StringBuilder();
        stb.append(nomFichClave);
        if (accion == 1) {
            stb.append(NOM_FICH_CLAVE_PUBLICA);
        } else {
            stb.append(NOM_FICH_CLAVE_PRIVADA);
        }
        nomFichClave = stb.toString();
        return nomFichClave;
    }

    /**
     * @param rutaFichero
     * @return
     */
    public static byte[] leerFichero(String rutaFichero) {
        byte[] bytes = null;
        try (FileInputStream fis = new FileInputStream(String.valueOf(Path.of(rutaFichero)))) {
            bytes = fis.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.println("El fichero no fué encontrado");
        } catch (IOException e) {
            System.out.println("Fallo al leer el fichero");
        }
        return bytes;
    }

    public static String escribirFichero(String nomFich, String modo, Cipher cifrado) {
        try {
            FileInputStream fis = new FileInputStream(nomFich);

            try {
                FileOutputStream fos = new FileOutputStream(nomFich + modo);

                try {
                    BufferedInputStream is = new BufferedInputStream(fis);

                    try {
                        BufferedOutputStream os = new BufferedOutputStream(fos);

                        try {
                            byte[] buff = new byte[cifrado.getBlockSize()];

                            while (true) {
                                if (is.read(buff) == -1) {
                                    os.write(cifrado.doFinal());
                                    break;
                                }

                                os.write(cifrado.update(buff));
                            }
                        } catch (Throwable var13) {
                            try {
                                os.close();
                            } catch (Throwable var12) {
                                var13.addSuppressed(var12);
                            }

                            throw var13;
                        }

                        os.close();
                    } catch (Throwable var14) {
                        try {
                            is.close();
                        } catch (Throwable var11) {
                            var14.addSuppressed(var11);
                        }

                        throw var14;
                    }

                    is.close();
                } catch (Throwable var15) {
                    try {
                        fos.close();
                    } catch (Throwable var10) {
                        var15.addSuppressed(var10);
                    }

                    throw var15;
                }

                fos.close();
            } catch (Throwable var16) {
                try {
                    fis.close();
                } catch (Throwable var9) {
                    var16.addSuppressed(var9);
                }
            }

            fis.close();
        } catch (IOException var19) {
            System.out.println("ERROR: de E/S encriptando fichero");
        }
        nomFich += modo;
        return nomFich;
    }


    /**
     * @param clavePublica
     * @return
     */
    public static boolean escribirClavePublicaRSA(PublicKey clavePublica, String nomFichClavePublica) {
        X509EncodedKeySpec x509EncodedKeySpec = null;
        nomFichClavePublica = generarRuta("C:\\Users\\caguilar.INFO2\\IdeaProjects\\ClavePublicaPrivada\\src\\GeneracionClavesRSA\\Claves\\" + nomFichClavePublica, 1);
        boolean salir = false;
        try (FileOutputStream fosClavePublica = new FileOutputStream(nomFichClavePublica)) {
            x509EncodedKeySpec = new X509EncodedKeySpec(
                    clavePublica.getEncoded(), nomFichClavePublica);
            fosClavePublica.write(x509EncodedKeySpec.getEncoded());
            System.out.printf("Clave pública guardada en formato %s en fichero %s:\n%s\n",
                    x509EncodedKeySpec.getFormat(), nomFichClavePublica,
                    Base64.getEncoder().encodeToString(x509EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));  // clavePublica.getEncoded() tiene lo mismo);
            salir = true;
        } catch (IOException e) {
            System.out.println("Error de E/S escribiendo clave pública en fichero");
        }
        return salir;
    }


    /**
     * @param nomFichClave
     * @return
     */
    public static byte[] leerClavePublicaRSA(String nomFichClave) {
        byte[] clavePubCodif = null;

        try (FileInputStream fisClavePub = new FileInputStream(nomFichClave)) {
            clavePubCodif = fisClavePub.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave pública %s\n.", nomFichClave);

        } catch (IOException e) {
            System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.", nomFichClave);

        }
        return clavePubCodif;
    }


    /**
     * @param clavePrivada
     * @return
     */
    public static boolean escribirClavePrivadaRSA(PrivateKey clavePrivada, String nomFichClave) {
        boolean salir = false;
        nomFichClave = generarRuta("C:\\Users\\caguilar.INFO2\\IdeaProjects\\ClavePublicaPrivada\\src\\GeneracionClaveRSA\\Claves\\" + nomFichClave, 2);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = null;
        try (FileOutputStream fosClavePrivada = new FileOutputStream(nomFichClave)) {
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    clavePrivada.getEncoded(), ALGORITMO_CLAVE_PUBLICA);
            fosClavePrivada.write(pkcs8EncodedKeySpec.getEncoded());
            System.out.printf("Clave privada guardada en formato %s en fichero %s:\n%s\n",  // clavePrivada.getEncoded() tiene lo mismo
                    pkcs8EncodedKeySpec.getFormat(), nomFichClave,
                    Base64.getEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));
            salir = true;
        } catch (IOException e) {
            System.out.println("Error de E/S escribiendo clave privada en fichero");

        }
        return salir;
    }


    public static byte[] leerClavePrivadaRSA(String nomFichClave) {
        nomFichClave = GestionFicheros.generarRuta(nomFichClave, 2);
        byte clavePrivCodif[] = null;
        try (FileInputStream fisClavePriv = new FileInputStream(nomFichClave)) {
            clavePrivCodif = fisClavePriv.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave pública %s\n.", nomFichClave);
        } catch (IOException e) {
            System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.", nomFichClave);
        }
        return clavePrivCodif;
    }


}
