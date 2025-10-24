# keysafe
Projekt WSB DG - Grupa 5 - bezpieczeństwo teleinformatyczne
- Łukasz Poseł
- Michał Kocoń
- Hubert Koń

## Szybki start (lokalnie)

1. Utwórz i aktywuj virtualenv:

```bash
python -m venv .venv
. .venv/bin/activate
```

2. Zainstaluj zależności:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

3. Uruchom testy:

```bash
make test
```

4. Użyj CLI (przykłady):

```bash
# create (zostaniesz poproszony o master password)
make run ARGS="create --label mykey --bits 2048"

# list
make run ARGS="list"

# export public
make run ARGS="export-public <entry-id> --out pub.pem"

# decrypt private
make run ARGS="decrypt <entry-id>"
```

5. Uruchom prosty GUI (Flask):

```bash
make serve
# otwórz http://127.0.0.1:5000 w przeglądarce
```

Uwaga: GUI jest prostym demo i nie powinno być używane w produkcji bez dodatkowego zabezpieczenia.

# KeySafe CLI 🔐

Prosty menedżer kluczy RSA w Pythonie.

## Funkcje

- Generowanie kluczy RSA
- Szyfrowanie prywatnych kluczy (AES-GCM + Argon2id)
- Zapis w bezpiecznym formacie JSON

## Co potrafi program (krótki opis)

- Tworzy pary kluczy RSA i zapisuje publiczny PEM w jawnej formie.
- Prywatne klucze są zaszyfrowane symetrycznie przy użyciu AES-256-GCM. Klucz AES jest wyprowadzany z hasła głównego (master password) przy użyciu Argon2id (parametry w kodzie: time=2, memory_kb=65536, parallelism=1).
- Plik `keystore.json` przechowuje wpisy w formacie JSON; gdy jest zaszyfrowany, zawiera wrapper z polami `encrypted: true`, `enc_params` (salt, nonce, kdf) oraz base64 `ciphertext` całego store.
- CLI udostępnia polecenia: create, list, export-public, decrypt. Dodana jest także funkcja programowa `rotate_master` do rotacji hasła głównego.

## Backup i przywracanie

1. Backup: po prostu skopiuj zaszyfrowany plik `keystore.json` w bezpieczne miejsce. Ponieważ plik jest zaszyfrowany, backup pliku można traktować jako bezpieczny nośnik kopii zapasowej (o ile hasło główne nie wyciekło).

```bash
cp keystore.json /path/to/secure/backup/keystore.json.bak
```

2. Przywracanie: skopiuj backup z powrotem do katalogu projektu i upewnij się, że masz poprawne hasło główne, aby odszyfrować wpisy.

```bash
cp /path/to/secure/backup/keystore.json.bak keystore.json
# następnie użyj CLI lub funkcji w Pythonie, np.:
# make run ARGS="list"  # program zapyta o master password jeśli plik jest zaszyfrowany
```

### Zalecane praktyki przy backupie

- Przechowuj backup w bezpiecznym, ograniczonym miejscu (zaszyfrowany dysk, bezpieczne repozytorium, HSM lub bezpieczny serwer plików).
- Nie przesyłaj backupu przez niezaszyfrowane kanały. Plik zawiera zaszyfrowane dane — jednak bezpieczeństwo opiera się na tajności master password.
- Regularnie testuj przywracanie backupu na izolowanym środowisku.

### Przykładowy skrypt backup/restore (shell)

Poniżej przykład prostego skryptu bash, który tworzy kopię zapasową i zachowuje kilka wersji:

```bash
# create backup directory (once)
mkdir -p /var/backups/keysafe

# timestamped backup
cp keystore.json /var/backups/keysafe/keystore.json.$(date -u +%Y%m%dT%H%M%SZ)

# optionally keep a .bak symlink to the latest
ln -sf /var/backups/keysafe/keystore.json.$(date -u +%Y%m%dT%H%M%SZ) /var/backups/keysafe/keystore.json.bak
```

### Rotacja hasła głównego (master password)

Rotacja polega na odszyfrowaniu całego store przy użyciu starego hasła, a następnie ponownym zaszyfrowaniu z użyciem nowego hasła. Zalecane kroki:

1. Zrób backup obecnego pliku `keystore.json` (zanim dokonasz rotacji).
2. Uruchom rotację programowo lub ręcznie (przykład poniżej).

```python
from keystore import load_keystore_encrypted, save_keystore_encrypted

# wczytaj przy użyciu starego hasła
store = load_keystore_encrypted('keystore.json', 'stare-haslo')

# zapisz ponownie z nowym hasłem
save_keystore_encrypted('keystore.json', store['entries'], 'nowe-haslo')
```

Jeżeli coś pójdzie nie tak, przywróć backup i spróbuj ponownie.

3. Rotacja master password (przywrócenie + zmiana hasła):

Jeżeli chcesz zmienić master password po przywróceniu backupu, użyj funkcji `rotate_master` (dostępna programowo) lub skryptowo odszyfruj i zapisz ponownie używając nowego hasła:

```python
from keystore import load_keystore_encrypted, save_keystore_encrypted
store = load_keystore_encrypted('keystore.json', 'stare-haslo')
save_keystore_encrypted('keystore.json', store['entries'], 'nowe-haslo')
```

Uwaga: zawsze trzymaj backup przed rotacją na wypadek problemów z odzyskaniem.

## Wymagania

- Python 3.8+
- cryptography
- argon2-cffi

## Instalacja

```bash
pip install -r requirements.txt
