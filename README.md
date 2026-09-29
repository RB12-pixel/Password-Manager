PASSWORD MANAGER LOCALE - PWA per Termux
==========================================

1) Installazione dipendenze:
   pkg update
   pkg install python python-cryptography
   pip install flask

2) Copia questi 3 file in ~/pwmanager/ sul telefono:
   - app.py
   - sw.js
   - make_icons.py

3) Genera le icone (crea la cartella static/ con le PNG):
   cd ~/pwmanager
   python make_icons.py

4) Avvia il server:
   python app.py

5) Apri Chrome su:
   http://localhost:5000

6) Installa come app:
   Menu Chrome (⋮) -> "Installa app" / "Aggiungi a schermata Home"

Avvio in background (facoltativo):
   termux-wake-lock
   nohup python app.py > /dev/null 2>&1 &

Note:
- I dati sono cifrati in ~/vault.bin, protetti dalla master password.
- Se dimentichi la master password, i dati NON sono recuperabili.
- Fai backup periodici di ~/vault.bin (il file resta cifrato anche copiato altrove).
