package Main;

import CifradoRSA.CifradoRSA;
import GeneracionClaveRSA.CriptografiaRSA;

import java.security.KeyPair;
import java.security.SignatureSpi;
import java.util.Scanner;

public class Main {

    public static final String GENERAR_FICH_CLAVE_PUB = "Escribe el nombre del fichero donde quieres que se genere la clave publica";
    public static final String GENERAR_FICH_CLAVE_PRIV = "Escribe el nombre del fichero donde quieres que se genere la clave privada";
    public static final String PEDIR_FICH_CLAVE = "Escribe el nombre del archivo donde se encuentra la clave\n(Sin extensión, solo el nombre)";
    public static final String PEDIR_RUTA_FICH = "Escriba la ruta completa del archivo a encriptar";

    public static final String MENU = "Que desea hacer: \n" +
            "1 -> Generar un par de claves Publica/Privada RSA\n" +
            "2 -> Encriptar Fichero con clave privada\n" +
            "3 -> Desencriptar Fichero con clave pública\n" +
            "0 -> Salir";
    public static final String FALLO_MENU ="Su elección no entra entre las posibles";

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        menu(sc);

    }

    private static String pedir(Scanner sc, String petision) {
        System.out.println(petision);
        return sc.nextLine();
    }

    private static int parsearInt(String eleccion) {
        int num = -1;
        try {
            num = Integer.parseInt(eleccion);
        } catch (NumberFormatException e) {
            System.out.println("Esto no es un número");
        }
        return num;
    }


    private static void opcion1(Scanner sc, CriptografiaRSA claves){
        String nomFichClavePub = pedir(sc, GENERAR_FICH_CLAVE_PUB);
        String nomFichPriv = pedir(sc, GENERAR_FICH_CLAVE_PRIV);
        claves.generarParClaves(nomFichClavePub, nomFichPriv);
    }

    private static void opcion2(Scanner sc, CifradoRSA cifrado){
        String nomFichClave = pedir(sc, PEDIR_FICH_CLAVE);
        String rutaFich = pedir(sc, PEDIR_RUTA_FICH);
        cifrado.encriptarFichero(nomFichClave, rutaFich);
    }

    private static void opcion3(Scanner sc, CifradoRSA cifrado){
        String nomFichClave = pedir(sc, PEDIR_FICH_CLAVE);
        String rutaFich = pedir(sc, PEDIR_RUTA_FICH);
        cifrado.desencriptarFichero(nomFichClave, rutaFich);
    }


    private static void menu(Scanner sc) {
        int eleccion;
        boolean salir = false;
        do {
            try {
                eleccion = parsearInt(pedir(sc, MENU));
                switch (eleccion) {
                    case 1 -> {
                        CriptografiaRSA claves = new CriptografiaRSA();
                        opcion1(sc, claves);
                    }
                    case 2 -> {
                        CifradoRSA cifrado = new CifradoRSA();
                        opcion2(sc, cifrado);
                    }
                    case 3 -> {
                        CifradoRSA descifrado = new CifradoRSA();
                        opcion3(sc, descifrado);
                    }
                    case 0 -> {
                        System.out.println("Bye!");
                        salir = true;
                    }
                    default -> {
                        System.out.println(FALLO_MENU);
                    }
                }
            } catch (NumberFormatException e) {
                System.out.println("No introdujiste un número");
            }

        } while (!salir);
    }
}
