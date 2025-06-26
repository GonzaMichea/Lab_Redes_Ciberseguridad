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

    // Cargar clave pública del Gran Maestro desde archivo DER (para cifrar)
    RSA::PublicKey clave_publica_gm;
    FileSource file_pub("gm_publica.der", true);
    clave_publica_gm.BERDecode(file_pub);

    // Cargar clave privada de Lyra desde archivo DER (para firmar)
    RSA::PrivateKey clave_privada_lyra;
    FileSource file_priv("privada.der", true);
    clave_privada_lyra.BERDecode(file_priv);

    string mensaje = "Los archivos antiguos, código MPSH476, revelan la ubicación del séptimo pergamino perdido.";
    string mensaje_cifrado, firma;

    // Cifrar con clave pública del Gran Maestro
    RSAES_OAEP_SHA_Encryptor cifrador(clave_publica_gm);
    StringSource ss1(mensaje, true,
        new PK_EncryptorFilter(rng, cifrador,
            new StringSink(mensaje_cifrado)
        )
    );

    // Firmar con clave privada de Lyra
    RSASS<PSS, SHA256>::Signer firmador(clave_privada_lyra);
    StringSource ss2(mensaje, true,
        new SignerFilter(rng, firmador,
            new StringSink(firma)
        )
    );

    cout << "=== CIFRADO ASIMÉTRICO RSA CON ARCHIVOS DER ===" << endl;
    cout << "Mensaje original: " << mensaje << endl;
    cout << "\nMensaje cifrado (base64): ";
    StringSource ss3(mensaje_cifrado, true,
        new Base64Encoder(new FileSink(cout))
    );
    cout << "\n\nFirma digital (base64): ";
    StringSource ss4(firma, true,
        new Base64Encoder(new FileSink(cout))
    );
    cout << "\n\n=== INFORMACIÓN TÉCNICA ===" << endl;
    cout << "• Claves cargadas desde archivos DER" << endl;
    cout << "• Cifrado: RSA-OAEP con SHA-1" << endl;
    cout << "• Firma: RSA-PSS con SHA-256" << endl;
    cout << "• Archivos utilizados: gm_publica.der, privada.der" << endl;
    cout << endl;

    return 0;
}
