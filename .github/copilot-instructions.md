Porozumienia dla AI (Copilot / Agent)

Krótko i na temat — czego oczekujemy od agenta pracującego w repozytorium `keysafe`.

- Cel projektu: prosty menedżer kluczy RSA zapisujący zaszyfrowane prywatne klucze w pliku `keystore.json` przy użyciu Argon2id jako KDF i AES-256-GCM jako szyfrowania symetrycznego. Główne pliki: `keystore.py` (demo/implementacja), `key` (kod powielony), `keystore.json` (przykładowy plik danych).

- Najważniejsze miejsca do zmiany/analizy:
  - `keystore.py` — canonical implementation i demo interakcji: generowanie pary RSA, szyfrowanie prywatnego PEM, serializacja wpisów do `keystore.json`. Użyj tego pliku jako źródła prawidłowych formatów i nazw pól (`entries[].encrypted_private`, `enc_params.salt`, `enc_params.nonce`).
  - `key` — wydaje się być duplikatem `keystore.py` z drobnymi różnicami (np. import `timezone` brak/pyright ignore). Przy zmianach sprawdź, czy nie wprowadzasz niespójności między nimi — preferuj `keystore.py` jako jedyną prawidłową wersję lub zaproponuj konsolidację.
  - `keystore.json` — wzorcowy zapis; pokazuje jak serializowane są wartości salt/nonce (Base64) i gdzie trzyma się ciphertext.

- Konwencje i wzorce specyficzne dla projektu:
  - KDF: Argon2id (używa `argon2.low_level.hash_secret_raw`) z parametrami zdefiniowanymi w module (`ARGON2_TIME`, `ARGON2_MEMORY`, `ARGON2_PARALLELISM`). Nie zmieniaj parametrów bez wyraźnego powodu i testów kompatybilności zapisów.
  - Serializacja: PEM dla public key (tekst), zaszyfrowany prywatny klucz jest base64-encoded ciphertext w polu `encrypted_private`, a enc_params zawiera `salt` i `nonce` również w base64.
  - Czas: `created_at` używa ISO8601 z sufiksem Z w `keystore.py`. W `key` jest próba użycia `timezone.utc` — jeśli dodajesz timestampy, zachowaj format ISO8601 z Z.

- Typowe zadań dla agenta (konkretne przykłady):
  - Dodać funkcję listującą etykiety i identyfikatory wpisów z `keystore.json`.
  - Dodać CLI (np. argparse) z komendami: create, list, export-public, decrypt (przy proszeniu o master password) — wzór interakcji jest w `keystore.py`.
  - Zrefaktoryzować duplikację: uczynić `keystore.py` module, zaktualizować `key` albo usunąć duplikat po uzgodnieniu.

- Testy i sprawdzanie poprawności:
  - Repo nie zawiera testów. Przy dodawaniu testów: szybkie unit testy powinny sprawdzać tworzenie wpisu (`create_entry`) i poprawne odszyfrowanie (`decrypt_private`) z tym samym master password. Użyj małego pliku JSON w katalogu `tests/` i `pytest`.

- Bezpieczeństwo i ograniczenia, które agent musi zachować:
  - Nie loguj haseł w czystym tekście. W testach użyj fikcyjnych, krótkotrwałych wartości i czyść pliki testowe.
  - Nie zmieniaj mechanizmu serializacji (pola JSON) bez migracji i zachowania kompatybilności wstecznej.

- Pliki referencyjne i miejsca do przeglądu przy zmianach:
  - `/workspaces/keysafe/keystore.py` — główny kod referencyjny
  - `/workspaces/keysafe/key` — duplikat; sprawdź różnice
  - `/workspaces/keysafe/keystore.json` — przykład danych
  - `README.md` — minimalny opis projektu

- Format commitów i PR:
  - Krótkie, rzeczowe komunikaty. Przy zmianach API JSON dodaj migrację i aktualizację `keystore.json` przykładu.

Jeśli coś jest niejasne w projekcie (np. który plik traktować jako źródło prawdy: `keystore.py` czy `key`), zapytaj o oczekiwaną wersję; zaproponuj konsolidację i przygotuj patch.

Proszę o feedback: czy chcesz, żebym skonsolidował `key` i `keystore.py` teraz, albo dodał prosty CLI i kilka testów jako następne kroki?
