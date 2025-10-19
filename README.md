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

## Wymagania

- Python 3.8+
- cryptography
- argon2-cffi

## Instalacja

```bash
pip install -r requirements.txt
