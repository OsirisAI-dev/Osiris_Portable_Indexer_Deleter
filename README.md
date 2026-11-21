# Osiris Portable Files Indexer & Corrupted Files Checker / Deleter Suite

**English** · **[Français](#français)** · **[Deutsch](#deutsch)**

> 100% local, zero-dependency, portable file indexer with embedded media/document preview (including Video Picture-in-Picture) and a companion multi-format corrupted-file checker with 2-stage quarantine workflow.

| Feature | Osiris Files Indexer | Osiris Checker & Deleter |
|---|---|---|
| **Safety** | Strictly **Read-Only** & delete-protected | Strictly excludes **`C:\`** + 2-stage `_OSIRIS_QUARANTINE` |
| **Dependencies** | Zero (Python 3 stdlib + vanilla HTML/CSS/JS) | Zero (no `.bat` script, no online CDN) |
| **Languages** | `EN` / `FR` / `DE` live switch | `EN` / `FR` / `DE` live switch |
| **Platforms** | Windows (`.exe` or Python), macOS & Linux (`python3`) | Windows (`.exe` or Python), macOS & Linux (`python3`) |

---

## English

### Highlights
- **Folder View (Default) & Subfolders Toggle:** Opens directly on a clean **Root Folders** overview; click any root folder to deploy all files inside its tree flat, tick **Show Subfolders** for an indented hierarchy of every nested folder, or switch to **Files View** at any time.
- **Built-In Preview & Video PiP:** Click any filename to preview video, audio, images, PDFs, HTML (sandboxed), and code/text. Video preview includes speed controls (`0.5x–2x`) and **Picture-in-Picture (`PiP`)** (native OS PiP + floating mini-player fallback so playback continues while you browse). Browser-unreadable formats (e.g. `.avi`, `.wmv`, archives, binaries) keep their original category color and display a strikethrough eye icon with 1-click Explorer access.
- **45+ Format Corrupted-File Checker & Quarantine Deleter:** Hidden by default on the Indexer page — enable **Checker / Deletion Mode** in `PARAM.` to show the red trashbin button, or launch with `--deleter`. Includes **Deep Check** (ZIP/OpenXML CRC with zip-bomb limits, TAR/GZ/BZ2/XZ stream integrity, PDF `%%EOF`, MP4/MOV atoms, JPG/PNG trailers, JSON/XML checks, and browser media decode) and moves corrupt files to `_OSIRIS_QUARANTINE` for manual inspection before restoring or permanently deleting.
- **True Extract-and-Run & Auto-Exit (Zero Python Needed):** The Windows Release ZIP bundles the official signed Python 3.12 embeddable runtime in `_osiris_runtime/` (~11 MB), so `Osiris_Indexer_Deleter.exe` launches the full Indexer + Deleter backend immediately on any Windows PC without Python installed (with an automatic PowerShell fallback if `_osiris_runtime/` is omitted). Closing the last open Indexer/Deleter tab automatically shuts down the background server cleanly within ~3 seconds (safe USB ejection).

### Quick Start
- **Windows (Portable Release ZIPs — choose one from Releases):**
  - **`Osiris_Portable_Indexer_Deleter_Suite_full.zip` (~11 MB):** Self-contained extract-and-run bundle with signed offline Python 3.12 runtime (`_osiris_runtime/`) — **recommended for PCs without Python**.
  - **`Osiris_Portable_Indexer_Deleter_Suite_lite.zip` (~160 KB):** Ultra-lightweight package for PCs that already have Python 3.10+ installed (or PowerShell offline fallback).
  - Extract to any drive or USB key and double-click `Osiris_Indexer_Deleter.exe`.
  - Optional Desktop & Start Menu shortcuts: `Osiris_Indexer_Deleter.exe --install`
  - Direct Deleter launch: `Osiris_Indexer_Deleter.exe --deleter`
- **From Source (Windows / macOS / Linux — Python 3.10+):**
  ```bash
  python3 files_indexer.py
  ```
  *(Open `http://127.0.0.1:8765/` for the Indexer, or `http://127.0.0.1:8765/deleter` for the Checker & Deleter.)*

### Build `Osiris_Indexer_Deleter.exe` From Source (Windows)
No Visual Studio needed — uses the built-in .NET Framework 4 C# compiler:
```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  /nologo /target:winexe /optimize+ `
  /win32icon:"FILES INDEXATION_DELETER\osiris_suite.ico" `
  /out:"Osiris_Indexer_Deleter.exe" `
  "src\OsirisLauncher.cs"
```

### Security Model
See [SECURITY.md](SECURITY.md) for the full local threat model: loopback-only binding (`127.0.0.1`), per-session CSRF token (`X-Osiris-Token`), strict `Host`/`Origin`/`Sec-Fetch-Site` validation, `X-Frame-Options: DENY`, CSP-sandboxed active file previews, `C:\` exclusion, NTFS ADS/symlink/traversal rejection, decompression-bomb caps, and Base64 `-EncodedCommand` PowerShell execution.

*(Tip for local development: run `git update-index --skip-worktree files_index_data.js` so your local drive snapshot is never accidentally staged.)*

---

## Français

### Points forts
- **Vue Dossiers (par défaut) & case Sous-dossiers :** S'ouvre directement sur les **dossiers racines** ; cliquez sur un dossier racine pour déployer à plat tous les fichiers de son arborescence, cochez **Sous-dossiers** pour afficher toute la hiérarchie indentée, ou passez en **Vue Fichiers** à tout moment.
- **Lecteur intégré & PiP Vidéo :** Cliquez sur un fichier pour ouvrir l'aperçu vidéo, audio, image, PDF, HTML (sandbox) ou code/texte. Le lecteur vidéo intègre le réglage de vitesse (`0.5x–2x`) et le mode **Picture-in-Picture (`PiP`)** (PiP natif + mini-lecteur flottant pour continuer à naviguer). Les fichiers non décodables par le navigateur (`.avi`, `.wmv`, archives, binaires...) conservent leur couleur d'origine avec une icône d'œil barré et accès direct à l'Explorateur.
- **Vérificateur 45+ formats & Quarantaine :** Masqué par défaut sur l'Indexeur — activez **Mode Vérification / Suppression** dans `PARAM.` pour afficher le bouton corbeille rouge, ou lancez avec `--deleter`. Inclut l'**Analyse Profonde** (CRC ZIP/Office anti-bombe ZIP, flux TAR/GZ/BZ2/XZ, `%%EOF` PDF, atomes MP4/MOV, fin JPG/PNG, JSON/XML et décodage média), exclut strictement **`C:\`** et déplace d'abord les fichiers corrompus dans `_OSIRIS_QUARANTINE` pour vérification manuelle avant restauration ou suppression définitive (aucun script `.bat`).
- **Extraire & Exécuter + Arrêt automatique (zéro Python requis) :** Le ZIP portable Windows intègre le runtime officiel signé Python 3.12 dans `_osiris_runtime/` (~11 Mo) : `Osiris_Indexer_Deleter.exe` lance immédiatement l'Indexeur et le Nettoyeur sur tout PC Windows sans Python installé (avec fallback PowerShell intégré). Fermer le dernier onglet Indexeur/Nettoyeur arrête automatiquement le serveur en arrière-plan sous ~3 secondes.

### Démarrage rapide
- **Windows (ZIP Portables depuis Releases — 2 éditions) :**
  - **`Osiris_Portable_Indexer_Deleter_Suite_full.zip` (~11 Mo) :** Autonome avec runtime Python 3.12 signé intégré (`_osiris_runtime/`) — **recommandé pour les PC sans Python**.
  - **`Osiris_Portable_Indexer_Deleter_Suite_lite.zip` (~160 Ko) :** Version légère pour les PC disposant déjà de Python 3.10+ (avec fallback PowerShell).
  - Extrayez sur n'importe quel disque ou clé USB et double-cliquez sur `Osiris_Indexer_Deleter.exe`.
  - Raccourcis Bureau & Menu Démarrer (optionnel) : `Osiris_Indexer_Deleter.exe --install`
  - Ouverture directe du Nettoyeur : `Osiris_Indexer_Deleter.exe --deleter`
- **Depuis les sources (Windows / macOS / Linux — Python 3.10+) :**
  ```bash
  python3 files_indexer.py
  ```

---

## Deutsch

### Highlights
- **Ordneransicht (Standard) & Unterordner-Option:** Startet übersichtlich mit den **Stammordnern**; ein Klick klappt alle enthaltenen Dateien flach darunter auf. Aktivieren Sie **Unterordner** für die vollständige eingerückte Ordnerstruktur oder wechseln Sie jederzeit zur **Dateiansicht**.
- **Integrierte Vorschau & Video-PiP:** Dateinamen öffnen die Vorschau für Video, Audio, Bilder, PDF, HTML (Sandbox) und Code/Text. Der Videoplayer bietet Wiedergabegeschwindigkeiten (`0.5x–2x`) sowie **Bild-im-Bild (`PiP`)** (natives PiP + schwebender Mini-Player zum Weiterblättern). Im Browser nicht abspielbare Formate (`.avi`, `.wmv`, Archive, Binärdateien) behalten ihre originale Kategoriefarbe und zeigen ein durchgestrichenes Auge mit direktem Explorer-Zugriff.
- **45+ Formate Dateiprüfer & Quarantäne-Löscher:** Standardmäßig auf der Indexer-Seite ausgeblendet — aktivieren Sie **Prüf- & Löschmodus** in `EINST.`, um die rote Papierkorb-Schaltfläche einzublenden, oder starten Sie mit `--deleter`. Bietet **Tiefenprüfung** (ZIP/Office-CRC mit ZIP-Bomb-Schutz, TAR/GZ/BZ2/XZ-Streams, PDF-`%%EOF`, MP4/MOV-Atome, JPG/PNG, JSON/XML und Medien-Dekodierung), schließt **`C:\`** strikt aus und verschiebt defekte Dateien zuerst nach `_OSIRIS_QUARANTINE` zur manuellen Prüfung vor Wiederherstellung oder endgültigem Löschen (kein `.bat`-Skript).
- **Entpacken & Starten + Auto-Stopp (kein Python erforderlich):** Das Windows-Release-ZIP enthält die offizielle signierte Python-3.12-Embeddable-Laufzeit in `_osiris_runtime/` (~11 MB), sodass `Osiris_Indexer_Deleter.exe` Indexer & Dateiprüfer sofort auf jedem Windows-PC ohne installiertes Python startet (inkl. PowerShell-Fallback). Beim Schließen des letzten offenen Tabs beendet sich der Hintergrundserver automatisch nach ~3 Sekunden.

### Schnellstart
- **Windows (Portable ZIPs unter Releases — 2 Editionen):**
  - **`Osiris_Portable_Indexer_Deleter_Suite_full.zip` (~11 MB):** Vollständiges Entpacken-&-Starten-Paket mit signierter Python-3.12-Laufzeit (`_osiris_runtime/`) — **empfohlen für PCs ohne Python**.
  - **`Osiris_Portable_Indexer_Deleter_Suite_lite.zip` (~160 KB):** Leichtgewicht-Paket für PCs mit bereits installiertem Python 3.10+ (inkl. PowerShell-Fallback).
  - Auf ein beliebiges Laufwerk oder einen USB-Stick entpacken und `Osiris_Indexer_Deleter.exe` doppelklicken.
  - Optionale Desktop-/Startmenü-Verknüpfungen: `Osiris_Indexer_Deleter.exe --install`
  - Dateiprüfer direkt starten: `Osiris_Indexer_Deleter.exe --deleter`
- **Aus dem Quellcode (Windows / macOS / Linux — Python 3.10+):**
  ```bash
  python3 files_indexer.py
  ```

---

## Project Structure

```text
.
├── FILES_INDEXATION_SYSTEM.html              # Portable Indexer web UI
├── files_indexer.py                          # Local loopback HTTP server & 45+ format backend
├── files_index_data.js                       # Clean null snapshot template
├── OSIRIS_INSTRUCTIONS_README.txt            # Offline multilingual user guide (EN / FR / DE)
├── FILES INDEXATION_DELETER/
│   ├── CHECKER_DELETER.html                  # Corrupted Files Checker & Quarantine UI
│   ├── osiris_suite.ico                      # Blue & gold Osiris suite icon
│   └── osiris_deleter.ico                    # Crimson-rose modern trashbin icon
├── src/
│   └── OsirisLauncher.cs                     # Windows .NET 4 launcher source
├── .github/workflows/release.yml             # Automated Windows build & release CI
├── SECURITY.md                               # Security model & defenses
└── LICENSE                                   # MIT License
```

## License

Released under the [MIT License](LICENSE).
