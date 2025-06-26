#include <iostream>
#include <string>
#include <fstream>

// Cabeceras de Crypto++
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>

// Usar namespaces para simplificar el código
using namespace CryptoPP;
using namespace std;

// --- Declaración de funciones ---
void cifrarMensaje();
void descifrarMensaje();


int main() {
    int opcion;

    while (true) {
        cout << "\n======================================" << endl;
        cout << "   MENÚ DE CIFRADO SIMÉTRICO AES" << endl;
        cout << "======================================" << endl;
        cout << "1. Cifrar mensaje y guardar en archivo" << endl;
        cout << "2. Descifrar mensaje desde archivo" << endl;
        cout << "0. Salir" << endl;
        cout << "--------------------------------------" << endl;
        cout << "Seleccione una opción: ";

        cin >> opcion;

        // Limpiar el buffer de entrada para evitar problemas
        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            opcion = -1; // Asignar una opción inválida
        }

        switch (opcion) {
            case 1:
                cifrarMensaje();
                break;
            case 2:
                descifrarMensaje();
                break;
            case 0:
                cout << "Saliendo del programa..." << endl;
                return 0;
            default:
                cout << "Opción no válida. Por favor, intente de nuevo." << endl;
                break;
        }
    }

    return 0;
}

// --- Implementación de la función de cifrado ---
void cifrarMensaje() {
    try {
        string keyHex = "6F708192A3B4C5D6E7F8A22022730072"; // Clave de 128 bits
        string mensaje = "La cámara descansa bajo el sauce llorón en el jardín del martillo.";
        
        cout << "\n--- INICIANDO PROCESO DE CIFRADO ---" << endl;
        cout << "Mensaje original: " << mensaje << endl;
        cout << "Clave (hex) utilizada: " << keyHex << endl;
        
        // 1. Convertir la clave de hexadecimal a binario
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
        
        // 2. Generar un Vector de Inicialización (IV) aleatorio
        AutoSeededRandomPool rng;
        SecByteBlock iv(AES::BLOCKSIZE);
        rng.GenerateBlock(iv, iv.size());
        
        // 3. Cifrar el mensaje usando AES en modo CBC
        string cifrado;
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);
        
        StringSource(mensaje, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(cifrado)
            )
        );
        
        // 4. Convertir IV y texto cifrado a hexadecimal para su visualización y almacenamiento
        string cifradoHex, ivHex;
        StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(ivHex)));
        StringSource(cifrado, true, new HexEncoder(new StringSink(cifradoHex)));
        
        cout << "\n--- RESULTADO DEL CIFRADO ---" << endl;
        cout << "IV (hex): " << ivHex << endl;
        cout << "Mensaje cifrado (hex): " << cifradoHex << endl;
        
        // 5. Guardar resultados en el archivo "cifrado.txt"
        ofstream outputFile("cifrado.txt");
        if (outputFile.is_open()) {
            outputFile << ivHex << endl;
            outputFile << cifradoHex << endl;
            outputFile.close();
            cout << "\n>>> Operación exitosa: IV y mensaje cifrado guardados en 'cifrado.txt'" << endl;
        } else {
            cerr << "\nError: No se pudo abrir el archivo 'cifrado.txt' para escribir." << endl;
        }

    } catch (const Exception& e) {
        cerr << "\nError de Crypto++: " << e.what() << endl;
    }
}

// --- Implementación de la función de descifrado ---
void descifrarMensaje() {
    try {
        cout << "\n--- INICIANDO PROCESO DE DESCIFRADO ---" << endl;

        // 1. Leer IV y texto cifrado desde el archivo
        string ivHex, cifradoHex;
        ifstream inputFile("cifrado.txt");
        if (!inputFile.is_open()) {
            cerr << "Error: No se pudo abrir 'cifrado.txt'." << endl;
            return;
        }
        
        getline(inputFile, ivHex);
        getline(inputFile, cifradoHex);
        inputFile.close();

        cout << "Datos leídos desde 'cifrado.txt':" << endl;
        cout << "IV (hex): " << ivHex << endl;
        
        // 2. Preparar la clave (debe ser idéntica a la del cifrado)
        string keyHex = "6F708192A3B4C5D6E7F8A22022730072";
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

        // 3. Decodificar IV y texto cifrado de hexadecimal a binario
        SecByteBlock iv(AES::BLOCKSIZE);
        StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));
        
        string cifrado;
        StringSource(cifradoHex, true, new HexDecoder(new StringSink(cifrado)));

        // 4. Configurar y ejecutar el descifrado
        string recuperado;
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource(cifrado, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(recuperado)
            )
        );

        // 5. Mostrar el mensaje recuperado
        cout << "\n--- RESULTADO DEL DESCIFRADO ---" << endl;
        cout << "Mensaje recuperado: " << recuperado << endl;
        cout << "\n>>> Operación de descifrado completada." << endl;

    } catch (const Exception& e) {
        cerr << "\nError de Crypto++: " << e.what() << endl;
    }
}