#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>
#include <cryptopp/oaep.h>

using namespace std;
using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Cargar clave privada del Gran Maestro desde archivo DER (para descifrar)
    RSA::PrivateKey clave_privada_gm;
    FileSource file_priv_gm("gm_privada.der", true);
    clave_privada_gm.BERDecode(file_priv_gm);

    // Cargar clave pública de Lyra desde archivo DER (para verificar firma)
    RSA::PublicKey clave_publica_lyra;
    FileSource file_pub_lyra("publica.der", true);
    clave_publica_lyra.BERDecode(file_pub_lyra);

    // Para este ejemplo, necesitamos el mensaje cifrado y la firma
    // En un caso real, estos vendrían de archivos o entrada del usuario
    cout << "Ingrese el mensaje cifrado (base64): ";
    string mensaje_cifrado_b64;
    getline(cin, mensaje_cifrado_b64);

    cout << "Ingrese la firma (base64): ";
    string firma_b64;
    getline(cin, firma_b64);

    // Decodificar de base64
    string mensaje_cifrado, firma;
    StringSource ss1(mensaje_cifrado_b64, true,
        new Base64Decoder(new StringSink(mensaje_cifrado))
    );
    StringSource ss2(firma_b64, true,
        new Base64Decoder(new StringSink(firma))
    );

    try {
        // Descifrar con clave privada del Gran Maestro
        string mensaje_descifrado;
        RSAES_OAEP_SHA_Decryptor descifrador(clave_privada_gm);
        StringSource ss3(mensaje_cifrado, true,
            new PK_DecryptorFilter(rng, descifrador,
                new StringSink(mensaje_descifrado)
            )
        );

        // Verificar firma con clave pública de Lyra
        RSASS<PSS, SHA256>::Verifier verificador(clave_publica_lyra);
        bool firma_valida = false;
        try {
            // Método directo de verificación
            firma_valida = verificador.VerifyMessage(
                (const CryptoPP::byte*)mensaje_descifrado.data(), 
                mensaje_descifrado.size(),
                (const CryptoPP::byte*)firma.data(), 
                firma.size()
            );
        } catch (const Exception& e) {
            firma_valida = false;
        }

        cout << "\n=== RESULTADO DEL DESCIFRADO Y VERIFICACIÓN ===" << endl;
        cout << "Mensaje descifrado: " << mensaje_descifrado << endl;
        cout << "Estado de la firma: " << (firma_valida ? "VÁLIDA" : "INVÁLIDA") << endl;
        
    } catch (const Exception& e) {
        cout << "Error en el proceso: " << e.what() << endl;
        return 1;
    }

    cout << "\n=== INFORMACIÓN TÉCNICA ===" << endl;
    cout << "• Descifrado: RSA-OAEP con SHA-1" << endl;
    cout << "• Verificación: RSA-PSS con SHA-256" << endl;
    cout << "• Archivos utilizados: gm_privada.der, publica.der" << endl;

    return 0;
}
