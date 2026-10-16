# Registrazione utenti

Avvia il progetto con Python 3.10 o successivo:

```powershell
python server.py
```

Apri poi [http://localhost:8000](http://localhost:8000). La pagina iniziale permette l'accesso; il collegamento **Registrati** apre il form di creazione account. Il server conserva gli utenti nel file SQLite `users.db`, creato automaticamente alla prima esecuzione.

Le password non sono memorizzate in chiaro: vengono salvate con hash PBKDF2 e sale casuale.
