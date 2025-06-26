#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <string>
#include <fstream>

using namespace CryptoPP;
using namespace std;

int main() {
    try {
        // --- 1. Definir la misma clave que se usó en el cifrado ---
        // Clave: 6F708192 A3B4C5D6 E7F8A2 + ROL (202273007-2)
        string keyHex = "6F708192A3B4C5D6E7F8A22022730072";
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

        // --- 2. Leer IV y texto cifrado del archivo ---
        string ivHex, cifradoHex;
        ifstream inputFile("cifrado.txt");
        if (!inputFile.is_open()) {
            cerr << "Error: No se pudo abrir el archivo 'cifrado.txt' para leer." << endl;
            return 1;
        }
        
        // Leer la primera línea para el IV y la segunda para el texto cifrado
        getline(inputFile, ivHex);
        getline(inputFile, cifradoHex);
        inputFile.close();

        // --- 3. Decodificar IV y texto cifrado de hexadecimal a binario ---
        SecByteBlock iv(AES::BLOCKSIZE);
        StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

        string cifrado;
        StringSource(cifradoHex, true, new HexDecoder(new StringSink(cifrado)));

        // --- 4. Configurar y ejecutar el descifrado AES-CBC ---
        string recuperado;
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        // El StreamTransformationFilter aplica el descifrado
        StringSource(cifrado, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(recuperado)
            )
        );

        // --- 5. Mostrar resultados ---
        cout << "=== DESCIFRADO SIMÉTRICO AES ===" << endl;
        cout << "Archivo de entrada: cifrado.txt" << endl;
        cout << "Clave (hex) utilizada: " << keyHex << endl;
        cout << "IV (hex) leido del archivo: " << ivHex << endl;
        
        cout << "\n=== MENSAJE RECUPERADO ===" << endl;
        cout << recuperado << endl;
        
        cout << "\n>>> Operacion de descifrado exitosa." << endl;

    } catch (const Exception& e) {
        cerr << "Error de Crypto++: " << e.what() << endl;
        // Este error puede ocurrir si la clave es incorrecta o los datos están corruptos.
        return 1;
    }

    return 0;
}