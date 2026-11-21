================================================================================
OSIRIS PORTABLE FILES INDEXER & CORRUPTED FILES CHECKER / DELETER SUITE
Multilingual User Guide  |  EN  /  FR  /  DE
================================================================================

--------------------------------------------------------------------------------
[EN] ENGLISH INSTRUCTIONS
--------------------------------------------------------------------------------
1. PORTABLE QUICK START (WINDOWS, ANY DRIVE OR USB KEY)
   - Two portable packages are available:
       * "..._full.zip" (~11 MB): Includes "_osiris_runtime" (signed official
         Python 3.12 embeddable runtime). Extract and run on ANY Windows PC
         with ZERO Python installed.
       * "..._lite.zip" (~160 KB): Lightweight edition for PCs that already
         have Python 3.10+ installed (falls back to built-in PowerShell offline
         indexing if Python is missing).
   - Extract all files to any folder or drive root (internal HDD/SSD, external
     drive, or USB flash key), then double-click "Osiris_Indexer_Deleter.exe"
     (blue & gold Osiris icon). No installer wizard and no .bat script required.
   - The app detects the current drive automatically, starts the local loopback
     server (127.0.0.1:8765) immediately, opens FILES_INDEXATION_SYSTEM.html in
     your browser, and indexes your drive on first launch.
   - Closing the last open Indexer / Deleter browser tab automatically shuts
     down the background server cleanly within ~3 seconds (releasing drive/USB
     locks automatically).
   - macOS / Linux: Run "python3 files_indexer.py" from the extracted folder.

2. OPTIONAL DESKTOP & START MENU SHORTCUTS (WINDOWS)
   - Click "Install Shortcuts" inside the Files Checker / Deleter page, OR run:
       Osiris_Indexer_Deleter.exe --install
   - Creates two portable shortcuts pointing to your extracted folder:
       * Osiris Files Indexer (blue & gold Osiris icon)
       * Osiris Files Checker & Deleter (modern crimson trashbin icon)

3. USING OSIRIS FILES INDEXER (FILES_INDEXATION_SYSTEM.html)
   - READ-ONLY & DELETE PROTECTED: No files can be deleted or modified from the
     Indexer interface or API.
   - FOLDER VIEW (DEFAULT) & SHOW SUBFOLDERS:
       * Opens in Folder View by default, displaying Root Folders only.
       * Click any root folder to deploy all files inside its tree flat.
       * Tick "Show Subfolders" in the filter bar to display all nested
         subfolders hierarchically with indentation.
       * Switch to "Files View" at any time to display every file flat.
   - QUICK JUMP TO TOP ("TOP ↑"): Click the floating or bar "TOP ↑" button to
     jump back to the top instantly.
   - SEARCH, PREVIEW & VIDEO PICTURE-IN-PICTURE (PiP):
       * Press "/" or Ctrl+K to search by Name, Type, or Path.
       * Click any filename to preview Video, Audio, Images, PDF, HTML, or Code
         (supports MP4, WEBM, OGV, MOV, 3GP, Chromium MKV, MP3, AAC, M4A/M4B,
         OGG/OPUS, FLAC, WAV, JPG, PNG, GIF, WEBP, AVIF, SVG, PDF, and text).
       * Video Preview includes playback speeds (0.5x–2x) and a PiP button
         (native OS Picture-in-Picture + floating mini-player fallback so video
         keeps playing while you continue browsing the index).
       * Files that cannot be decoded natively in the browser (e.g. AVI, WMV,
         archives, executables, binary docs) display a strikethrough eye icon
         while keeping their original category color — click PATH or "Open
         Folder" to launch them with your system app (VLC, etc.).
   - CUSTOMIZE (PARAM.): Change title, font, size display mode, Light/Dark
     theme, background preset/image, opacity, language (FR / DE / EN), OS/cache
     folder exclusions, and toggle the Checker / Deleter button visibility.

4. USING CORRUPTED FILES CHECKER & QUARANTINE DELETER
   - Enable "Checker / Deletion Mode" in PARAM. to display the red trashbin
     "FILES CHECKER / DELETER" button (opens in a new tab), OR launch:
       Osiris_Indexer_Deleter.exe --deleter
   - STRICT C:\ PROTECTION: The Windows system drive (C:\) is blocked from all
     Deleter scan, quarantine, restore, and delete operations.
   - DEEP CHECK (45+ FORMATS): Magic-byte signatures plus full ZIP/OpenXML CRC
     checks (with zip-bomb safety limits), TAR/GZ/BZ2/XZ streams, PDF %%EOF,
     MP4/MOV atoms, JPG/PNG trailers, JSON/XML validation, and media decoding.
   - 2-STAGE QUARANTINE WORKFLOW (NO .BAT SCRIPT REQUIRED):
       Stage 1: Move corrupted files safely into "_OSIRIS_QUARANTINE".
       Stage 2: Manually inspect quarantined files ("Open in Explorer" /
                "Check"), then either "Restore" false positives or permanently
                delete verified corrupt files.

5. SECURITY & PRIVACY
   - 100% local (zero internet/CDN requests, zero telemetry).
   - Loopback-only HTTP server protected with per-session CSRF tokens, strict
     Host/Origin checks, clickjacking headers, and CSP-sandboxed file previews.


--------------------------------------------------------------------------------
[FR] INSTRUCTIONS EN FRANÇAIS
--------------------------------------------------------------------------------
1. DÉMARRAGE RAPIDE PORTABLE (WINDOWS, TOUT DISQUE OU CLÉ USB)
   - Deux éditions portables sont disponibles :
       * "..._full.zip" (~11 Mo) : Inclut « _osiris_runtime » (runtime officiel
         Python 3.12 signé). Extrayez et lancez sur TOUT PC Windows sans Python.
       * "..._lite.zip" (~160 Ko) : Édition légère pour les PC ayant déjà
         Python 3.10+ (bascule sur PowerShell hors-ligne sinon).
   - Extrayez dans n'importe quel dossier ou à la racine d'un disque/clé USB,
     puis double-cliquez sur "Osiris_Indexer_Deleter.exe" (icône bleu et or).
     Aucun installateur ni script .bat n'est requis.
   - L'application détecte automatiquement le lecteur, démarre instantanément
     le serveur local sécurisé (127.0.0.1:8765), ouvre le navigateur et indexe
     votre disque au premier lancement.
   - La fermeture du dernier onglet Indexeur / Nettoyeur arrête automatiquement
     le serveur local en arrière-plan en ~3 secondes (libérant les verrous USB).
   - macOS / Linux : exécutez "python3 files_indexer.py" dans le dossier.

2. RACCOURCIS BUREAU & MENU DÉMARRER (OPTIONNEL, WINDOWS)
   - Cliquez sur « Installer Raccourcis » dans le Nettoyeur, ou exécutez :
       Osiris_Indexer_Deleter.exe --install
   - Crée deux raccourcis portables :
       * Osiris Files Indexer (icône Osiris bleu et or)
       * Osiris Files Checker & Deleter (icône corbeille rouge moderne)

3. UTILISATION DE L'INDEXEUR (FILES_INDEXATION_SYSTEM.html)
   - LECTURE SEULE & ANTI-SUPPRESSION : Aucun fichier ne peut être modifié ou
     supprimé depuis l'Indexeur.
   - VUE DOSSIERS (PAR DÉFAUT) & SOUS-DOSSIERS :
       * S'ouvre par défaut en Vue Dossiers sur les dossiers racines.
       * Cliquez sur un dossier racine pour déployer à plat tous les fichiers
         de son arborescence.
       * Cochez « Sous-dossiers » dans la barre de filtres pour afficher tous
         les sous-dossiers imbriqués avec indentation hiérarchique.
       * Basculez vers « Vue Fichiers » à tout moment pour tout afficher à plat.
   - RETOUR EN HAUT (« HAUT ↑ ») : Remontez instantanément en un clic.
   - RECHERCHE, APERÇU & MODE PiP VIDÉO :
       * Appuyez sur "/" ou Ctrl+K pour rechercher par Nom, Type ou Chemin.
       * Cliquez sur un fichier pour le lecteur/aperçu intégré (MP4, WEBM, OGV,
         MOV, 3GP, MKV sur Chromium, MP3, AAC, M4A/M4B, OGG/OPUS, FLAC, WAV,
         JPG, PNG, GIF, WEBP, AVIF, SVG, PDF et code/texte).
       * Le lecteur vidéo inclut vitesses (0.5x–2x) et mode Picture-in-Picture
         (PiP natif + mini-lecteur flottant pour continuer à naviguer).
       * Les formats non décodables nativement par le navigateur (AVI, WMV,
         archives, exécutables, documents binaires) affichent un œil barré tout
         en gardant la couleur d'origine de leur catégorie — cliquez sur CHEMIN
         ou « Ouvrir le dossier » pour les ouvrir avec VLC ou votre app système.
   - PARAMÈTRES (PARAM.) : Personnalisez langue (FR / DE / EN), thème Clair /
     Sombre, police, fond, opacité, exclusion système/cache et affichage du
     bouton Vérificateur & Nettoyeur.

4. VÉRIFICATEUR MULTI-FORMATS & NETTOYEUR EN QUARANTAINE
   - Activez « Mode Vérification / Suppression » dans PARAM. pour afficher le
     bouton corbeille rouge « VÉRIFICATEUR & NETTOYEUR » (nouvel onglet), ou
     lancez : Osiris_Indexer_Deleter.exe --deleter
   - EXCLUSION STRICTE DE C:\ : Le lecteur système C:\ est totalement bloqué.
   - ANALYSE PROFONDE (45+ FORMATS) : Signatures magiques + intégrité CRC
     ZIP/Office (avec protection anti-bombe ZIP), flux TAR/GZ/BZ2/XZ, %%EOF
     PDF, atomes MP4/MOV, fin JPG/PNG, JSON/XML et décodage média.
   - WORKFLOW QUARANTAINE EN 2 ÉTAPES (SANS SCRIPT .BAT) :
       Étape 1 : Déplacez les fichiers corrompus vers "_OSIRIS_QUARANTINE".
       Étape 2 : Vérifiez-les manuellement (« Ouvrir dans Explorateur » ou
                 « Vérifier »), puis restaurez ou supprimez définitivement.

5. SÉCURITÉ & CONFIDENTIALITÉ
   - 100 % local (aucune connexion Internet, aucun CDN, aucune télémétrie).
   - Serveur loopback sécurisé par jeton CSRF de session, contrôle strict
     Host/Origin, protection anti-clickjacking et aperçus en sandbox CSP.


--------------------------------------------------------------------------------
[DE] DEUTSCHE ANLEITUNG
--------------------------------------------------------------------------------
1. PORTABLER SCHNELLSTART (WINDOWS, JEDES LAUFWERK / USB-STICK)
   - Zwei portable Pakete stehen zur Wahl:
       * "..._full.zip" (~11 MB): Enthält „_osiris_runtime“ (signierte
         Python-3.12-Embeddable-Laufzeit) – sofort auf jedem Windows-PC ganz
         ohne installiertes Python lauffähig.
       * "..._lite.zip" (~160 KB): Leichtgewicht-Version für PCs mit bereits
         installiertem Python 3.10+ (mit PowerShell-Fallback).
   - Alle Dateien auf ein beliebiges Laufwerk oder einen USB-Stick entpacken
     und "Osiris_Indexer_Deleter.exe" per Doppelklick starten – ohne Installer
     und ohne .bat-Skript.
   - Das Laufwerk wird automatisch erkannt, der lokale Server (127.0.0.1:8765)
     startet sofort, öffnet den Browser und indexiert beim ersten Start.
   - Beim Schließen des letzten offenen Indexer-/Prüfer-Tabs beendet sich der
     lokale Hintergrundserver automatisch nach ~3 Sekunden (gibt USB-Laufwerke
     sofort wieder frei).
   - macOS / Linux: "python3 files_indexer.py" im entpackten Ordner ausführen.

2. DESKTOP- & STARTMENÜ-VERKNÜPFUNGEN (OPTIONAL, WINDOWS)
   - Klicken Sie im Dateiprüfer auf „Verknüpfungen installieren“ oder starten
     Sie: Osiris_Indexer_Deleter.exe --install
   - Erstellt zwei portable Verknüpfungen:
       * Osiris Files Indexer (blau-goldenes Osiris-Symbol)
       * Osiris Files Checker & Deleter (modernes rotes Papierkorb-Symbol)

3. DATEI-INDEXER (FILES_INDEXATION_SYSTEM.html)
   - SCHREIBGESCHÜTZT: Im Indexer können keine Dateien gelöscht oder verändert
     werden.
   - ORDNERANSICHT (STANDARD) & UNTERORDNER:
       * Startet standardmäßig in der Ordneransicht mit Stammordnern.
       * Ein Klick auf einen Stammordner klappt alle enthaltenen Dateien flach
         darunter auf.
       * Aktivieren Sie „Unterordner“ in der Filterleiste für die hierarchische
         Anzeige aller verschachtelten Ebenen.
       * Wechseln Sie jederzeit zur „Dateiansicht“ für alle Dateien flach.
   - SCHNELL NACH OBEN („OBEN ↑“): Sofort zurück an den Seitenanfang springen.
   - SUCHE, VORSCHAU & VIDEO-PiP:
       * "/" oder Strg+K startet die Suche nach Name, Typ oder Pfad.
       * Klick auf Dateinamen öffnet die integrierte Vorschau (MP4, WEBM, OGV,
         MOV, 3GP, Chromium-MKV, MP3, AAC, M4A/M4B, OGG/OPUS, FLAC, WAV, JPG,
         PNG, GIF, WEBP, AVIF, SVG, PDF und Code/Text).
       * Videoplayer mit Geschwindigkeiten (0.5x–2x) und Bild-im-Bild (PiP,
         nativ + schwebender Mini-Player zum Weiterblättern).
       * Im Browser nicht nativ abspielbare Formate (z. B. AVI, WMV, Archive,
         Programme, Binärdokumente) zeigen bei originaler Kategoriefarbe ein
         durchgestrichenes Auge – PFAD / „Ordner öffnen“ öffnet den Explorer.
   - EINSTELLUNGEN (EINST.): Sprache (FR / DE / EN), Hell/Dunkel, Schriftart,
     Hintergrund, Deckkraft, Systemordner-Ausschluss und Prüfer-Schaltfläche.

4. BESCHÄDIGTE-DATEIEN-PRÜFER & QUARANTÄNE-LÖSCHER
   - In EINST. „Prüf- & Löschmodus“ aktivieren, um die rote Papierkorb-
     Schaltfläche „DATEIPRÜFER & BEREINIGER“ anzuzeigen, oder starten:
       Osiris_Indexer_Deleter.exe --deleter
   - STRENGER C:\-SCHUTZ: Laufwerk C:\ ist für alle Aktionen blockiert.
   - TIEFENPRÜFUNG (45+ FORMATE): Magic-Bytes plus ZIP/Office-CRC (mit
     ZIP-Bomb-Schutz), TAR/GZ/BZ2/XZ, PDF-%%EOF, MP4/MOV-Atome, JPG/PNG,
     JSON/XML-Prüfung und Medien-Dekodierung.
   - 2-STUFEN-QUARANTÄNE (OHNE .BAT-SKRIPT):
       Schritt 1: Beschädigte Dateien nach "_OSIRIS_QUARANTINE" verschieben.
       Schritt 2: Manuell im Explorer prüfen, dann wiederherstellen oder
                  endgültig löschen.

5. SICHERHEIT & DATENSCHUTZ
   - 100 % lokal (keine Internetabhängigkeiten, keine Telemetrie).
   - Loopback-Server mit Sitzungs-CSRF-Token, Host/Origin-Prüfung,
     Clickjacking-Schutz und CSP-Sandbox für Dateivorschauen.
================================================================================
