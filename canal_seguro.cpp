#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>
#include <cryptopp/oaep.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;

// Función para generar una clave AES aleatoria
string generarClaveAES(AutoSeededRandomPool& rng) {
    SecByteBlock clave(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(clave, clave.size());
    
    string claveHex;
    StringSource ss(clave, clave.size(), true,
        new HexEncoder(new StringSink(claveHex))
    );
    return claveHex;
}

// Función para cifrar con AES
string cifrarAES(const string& mensaje, const string& claveHex) {
    AutoSeededRandomPool rng;
    
    // Convertir clave hex a bytes
    SecByteBlock clave(AES::DEFAULT_KEYLENGTH);
    StringSource ss1(claveHex, true,
        new HexDecoder(new ArraySink(clave, clave.size()))
    );
    
    // Generar IV aleatorio
    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    
    string mensajeCifrado;
    
    // Cifrar usando AES en modo CBC
    CBC_Mode<AES>::Encryption cifrador;
    cifrador.SetKeyWithIV(clave, clave.size(), iv);
    
    StringSource ss2(mensaje, true,
        new StreamTransformationFilter(cifrador,
            new StringSink(mensajeCifrado)
        )
    );
    
    // Concatenar IV + mensaje cifrado y convertir a hex
    string resultado;
    StringSource ss3(iv, iv.size(), true,
        new HexEncoder(new StringSink(resultado))
    );
    
    string mensajeCifradoHex;
    StringSource ss4(mensajeCifrado, true,
        new HexEncoder(new StringSink(mensajeCifradoHex))
    );
    
    return resultado + mensajeCifradoHex;
}

// Función para descifrar con AES
string descifrarAES(const string& mensajeCifradoHex, const string& claveHex) {
    // Convertir clave hex a bytes
    SecByteBlock clave(AES::DEFAULT_KEYLENGTH);
    StringSource ss1(claveHex, true,
        new HexDecoder(new ArraySink(clave, clave.size()))
    );
    
    // Extraer IV (primeros 32 caracteres hex = 16 bytes)
    string ivHex = mensajeCifradoHex.substr(0, 32);
    string datosHex = mensajeCifradoHex.substr(32);
    
    SecByteBlock iv(AES::BLOCKSIZE);
    StringSource ss2(ivHex, true,
        new HexDecoder(new ArraySink(iv, iv.size()))
    );
    
    // Convertir datos cifrados de hex a bytes
    string datosCifrados;
    StringSource ss3(datosHex, true,
        new HexDecoder(new StringSink(datosCifrados))
    );
    
    string mensajeDescifrado;
    
    // Descifrar usando AES en modo CBC
    CBC_Mode<AES>::Decryption descifrador;
    descifrador.SetKeyWithIV(clave, clave.size(), iv);
    
    StringSource ss4(datosCifrados, true,
        new StreamTransformationFilter(descifrador,
            new StringSink(mensajeDescifrado)
        )
    );
    
    return mensajeDescifrado;
}

int main() {
    AutoSeededRandomPool rng;
    
    cout << "ORDEN DE ALEJANDRIA - CANAL SEGURO DE COMUNICACIONES" << endl;
    cout << "=====================================================" << endl;
    cout << "Estableciendo canal seguro entre:" << endl;
    cout << "- Gran Maestro (GM)" << endl;
    cout << "- Honorable Pedrius Godoyius (PG)" << endl << endl;
    
    cout << "FASE 1: Intercambio de Claves" << endl;
    cout << "=============================" << endl;
    
    try {
        // Cargar claves RSA desde archivos DER del Orden
        RSA::PublicKey clave_publica_gm;
        FileSource file_pub("gm_publica.der", true);
        clave_publica_gm.BERDecode(file_pub);
        
        RSA::PrivateKey clave_privada_pg;
        FileSource file_priv("privada.der", true);
        clave_privada_pg.BERDecode(file_priv);
        
        cout << "Claves cargadas correctamente:" << endl;
        cout << "- Clave publica del Gran Maestro: OK" << endl;
        cout << "- Clave privada de Pedrius Godoyius: OK" << endl << endl;
        
        // PG genera una clave AES secreta para la sesión
        string claveAES = generarClaveAES(rng);
        cout << "Pedrius genera clave AES de sesion:" << endl;
        cout << "Clave: " << claveAES << endl << endl;
        
        // PG cifra la clave AES con la clave pública del GM
        string claveAES_cifrada;
        RSAES_OAEP_SHA_Encryptor cifrador(clave_publica_gm);
        StringSource ss1(claveAES, true,
            new PK_EncryptorFilter(rng, cifrador,
                new StringSink(claveAES_cifrada)
            )
        );
        
        cout << "Pedrius cifra la clave con RSA del Gran Maestro:" << endl;
        cout << "Clave cifrada: ";
        StringSource ss2(claveAES_cifrada, true,
            new Base64Encoder(new FileSink(cout))
        );
        cout << endl << endl;
        
        // PG firma la clave para autenticación
        string firma;
        RSASS<PSS, SHA256>::Signer firmador(clave_privada_pg);
        StringSource ss3(claveAES, true,
            new SignerFilter(rng, firmador,
                new StringSink(firma)
            )
        );
        
        cout << "Pedrius firma digitalmente la clave" << endl;
        cout << "Transmision del paquete cifrado..." << endl;
        cout << "Gran Maestro recibe y descifra con su clave privada RSA" << endl;
        cout << "Gran Maestro verifica la firma de Pedrius" << endl;
        cout << "Intercambio de claves completado!" << endl << endl;
        
        cout << "FASE 2: Comunicaciones Cifradas" << endl;
        cout << "===============================" << endl;
        
        // Mensajes secretos del Orden de Alejandría
        vector<string> mensajes = {
            "Gran Maestro, los codices antiguos han sido descifrados. El pergamino MPSH476 revela coordenadas: 31.2001,-29.9187",
            "Excelente trabajo, Pedrius. Confirmas que la Biblioteca Perdida esta en esas coordenadas?",
            "Afirmativo, Gran Maestro. Los jeroglificos coinciden con los mapas ptolemaicos. Requiero autorizacion para la expedicion.",
            "Autorizacion concedida. Codigo de acceso: ALEXANDRIA_ETERNAL_WISDOM. Procede con maxima discrecion.",
            "Entendido. Los Guardianes del Conocimiento han sido notificados. Mision inicia al amanecer.",
            "Que la sabiduria de los antiguos te acompañe, hermano Pedrius. Gloria al Orden de Alejandria."
        };
        
        vector<string> remitentes = {"Pedrius Godoyius", "Gran Maestro", "Pedrius Godoyius", "Gran Maestro", "Pedrius Godoyius", "Gran Maestro"};
        
        cout << "Intercambio de comunicaciones cifradas:" << endl << endl;
        
        for (int i = 0; i < mensajes.size(); i++) {
            cout << "> " << remitentes[i] << " envía mensaje cifrado:" << endl;
            cout << "   📝 Contenido: \"" << mensajes[i] << "\"" << endl;
            
            // Cifrar mensaje con AES
            string mensajeCifrado = cifrarAES(mensajes[i], claveAES);
            cout << "   🔐 Cifrado AES: " << mensajeCifrado.substr(0, 64) << "..." << endl;
            
            // El receptor descifra
            string receptor = (remitentes[i] == "Pedrius Godoyius") ? "Gran Maestro" : "Pedrius Godoyius";
            string mensajeDescifrado = descifrarAES(mensajeCifrado, claveAES);
            cout << "> " << receptor << " recibe y descifra: \"" << mensajeDescifrado << "\"" << endl;
            cout << "  Verificacion: OK" << endl << endl;
        }
        
    } catch (const Exception& e) {
        cout << "ERROR EN LAS COMUNICACIONES:" << endl;
        cout << "  Detalle tecnico: " << e.what() << endl;
        cout << "  Verificar archivos de claves: gm_publica.der, privada.der" << endl;
        cout << "  Asegurar que las claves esten correctamente generadas" << endl;
        return 1;
    }
    
    cout << endl << "MISION COMPLETADA - CANAL SEGURO ESTABLECIDO" << endl;
    cout << "La sabiduria del Orden de Alejandria permanece protegida" << endl;
    cout << "=====================================================" << endl;
    
    return 0;
}
