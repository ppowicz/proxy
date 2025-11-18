# Warstwa Reverse-Proxy oraz Identyfikacji Użytkowników dla `*.ppowicz.pl`

## 1. Zakres funkcjonalny

- **Wielowarstwowa autentykacja użytkowników**: logowanie, rejestracja, egzekwowanie TOTP (obowiązkowe 2FA) oraz obsługa tymczasowych sesji.
- **Scentralizowane sesje między subdomenami**: współdzielone ciasteczka `session_id` i `pending_session` w domenie `.ppowicz.pl` oraz tokeny `proxy_auth` dla projektów hasłowych.
- **Reverse-proxy L7**: terminacja TLS, walidacja hosta, przekierowanie subdomen do portów lokalnych z zachowaniem nagłówków `X-Forwarded-*` i korekcją błędów.
- **Panel administracyjny i API JSON**: zarządzanie użytkownikami, rolami, uprawnieniami, logami HTTP i stanem projektów (dostępne na `admin.ppowicz.pl`).
- **Rejestrowanie i higiena logów**: sanetyzowane logi HTTP w bazie, retencja plików dziennika, redakcja nagłówków i ciał zawierających tajne dane.
- **Mechanizmy bezpieczeństwa**: limity żądań (login, rejestracja, 2FA), podpisywane tokeny HMAC dla projektów, hasła Argon2, szyfrowanie sekretów TOTP (Fernet).

---

## 2. Architektura logiczna

| Moduł | Rola w systemie |
| --- | --- |
| `proxy/proxy.py` | Główny serwer `HTTPServer` z obsługą certyfikatów LE, router subdomen, logika login/register/2FA/admin, forwardowanie do backendów. |
| `proxy/db.py` | Warstwa dostępu do PostgreSQL (użytkownicy, role, sesje, logi, tajne dane 2FA) wraz z operacjami transakcyjnymi. |
| `proxy/projects/*.json` | Definiuje mapowanie subdomena → port + opcjonalne `password` i `permission` dla poszczególnych projektów. |
| `proxy/sites/*.html` | Szablony (Jinja-less) dla loginu, rejestracji, panelu użytkownika, formularzy 2FA, haseł projektów, panelu admina, stron błędów. |
| `PROJECTS_ROOT` | Katalog systemowy z projektami aplikacyjnymi; skaner odświeża konfigurację co `SCAN_INTERVAL_SECONDS`. |

Przepływ żądania: klient → TLS na porcie 443 → `ProxyHandler.handle_proxy()` → kontrola subdomeny i ścieżki specjalnej → autoryzacja (sesja, permisja, hasło) → proxowanie HTTP → logowanie transakcji → odpowiedź.

---

## 3. Szczegółowe działanie proxy

1. **Walidacja hosta** – nagłówek `Host` musi kończyć się na `ROOT_DOMAIN` (lista dozwolonych sufiksów). Odchylenia kończą się odpowiedzią 404.
2. **Ładowanie konfiguracji projektów** – skaner regularnie wczytuje `proxy-config.json` każdego katalogu w `PROJECTS_ROOT`, przygotowując strukturę `PROJECTS` oraz listę błędnych wpisów.
3. **Ścieżki uprzywilejowane** – subdomena `ppowicz` obsługuje login, rejestrację, 2FA i panel użytkownika; subdomena `admin` obsługuje UI i API administracyjne.
4. **Forwarding L7** – dla zwykłych projektów handler zestawia połączenie `http.client.HTTPConnection` na `127.0.0.1:<port>`, przenosi nagłówki sans `Connection`/`Upgrade`, dokleja `X-Forwarded-For/Proto`, a następnie zwraca odpowiedź klientowi.
5. **Obsługa błędów backendu** – kody 4xx/5xx mapowane są na szablony HTML (`ERROR_TEMPLATE`) lub fallback; błędy połączenia kończą się 502 z odpowiednim logiem.
6. **Rejestracja ruchu** – każda transakcja trafia do `insert_http_log` wraz z kontekstem (IP, metoda, sanitized header/body, status, czasy backendowe, identyfikatory użytkownika i sesji).
7. **Konserwacja** – `maybe_cleanup_logs()` usuwa stare wpisy ze strumienia plikowego i tabeli `http_logs`; `maybe_reload_projects()` ogranicza koszt I/O dzięki odstępom czasowym.

---

## 4. Procedura uwierzytelniania i autoryzacji

### 4.1. Rejestracja
- Formularz HTML trafia na `POST /register`; dane przechodzą walidację syntaktyczną oraz limity IP (`REGISTER_RATE_LIMIT_PER_IP`).
- Nowy rekord `users` jest tworzony poprzez `create_user`, a konto oczekuje na aktywację administracyjną; użytkownik otrzymuje stronę „pending”.

### 4.2. Logowanie + 2FA
1. **Logowanie podstawowe** – `POST /login` sprawdza IP i użytkownika w limiterach (`LOGIN_RATE_LIMIT_*`), po czym weryfikuje hasło Argon2 (`verify_password`).
2. **Sesja tymczasowa** – niezależnie od dalszego przebiegu tworzona jest sesja UUID (`create_session`), zapisywana jako cookie `pending_session` (`SameSite=Strict`, `HttpOnly`, `Secure`).
3. **Gałąź użytkownika z 2FA**:
   - Jeśli konto posiada aktywne TOTP (`has_totp_enabled`), sesja otrzymuje stan `{"2fa_pending": true}` i użytkownik jest kierowany na `/login/2fa`.
   - Każde żądanie walidacyjne sprawdza limit `TWO_FA_RATE_LIMIT_PER_SESSION`, następnie używa `verify_totp_code`; sukces promuje sesję (patrz 4.3).
4. **Gałąź bez 2FA** – użytkownik zobowiązany jest do konfiguracji TOTP na `/login/setup-2fa`; serwer generuje sekret (`create_totp_secret`) i QR (biblioteka `qrcode`). Po poprawnym kodzie TOTP system oznacza 2FA jako włączone i promuje sesję.

### 4.3. Promocja i degradacja sesji
- **Promocja** – metoda `_promote_session` usuwa `pending_session` i wystawia `session_id` ważne globalnie. `extra_data` w tabeli `sessions` przechowuje flagi `2fa_verified`, `original_next` itd.
- **Degradacja / logout** – `/logout` usuwa `session_id` z bazy (`expire_session`) oraz czyści oba ciasteczka.
- **Autoryzacja zasobów** –
  - Projekty mogą wymagać `permission`; wówczas `user_has_permission` sprawdza, czy zalogowany użytkownik spełnia warunek.
  - Odrębnie dostępne jest hasło projektu: formularz ustawiający cookie `proxy_auth` z podpisanym tokenem (HMAC-SHA256). Token zawiera `subdomain`, fingerprint hasła i znacznik czasu.

---

## 5. Zarządzanie sesjami i cookie

| Cookie | Zakres | Cel | Uwagi |
| --- | --- | --- | --- |
| `pending_session` | `.ppowicz.pl` | Krótkotrwała sesja do momentu ukończenia 2FA | `SameSite=Strict`, max-age sterowany `PENDING_SESSION_MAX_AGE`. |
| `session_id` | `.ppowicz.pl` | Pełna sesja użytkownika po weryfikacji TOTP lub świadomym pominięciu | W bazie przechowywane są IP, UA i znaczniki `last_seen_at`. |
| `proxy_auth` | Subdomena projektu | Token dostępu do projektu chronionego hasłem | Preferowany format podpisany HMAC (`build_proxy_auth_token`); legacy base64 nadal rozpoznawany. |

Sesje w bazie obejmują `extra_data` (JSON) z informacjami o stanie 2FA oraz parametrach przepływu. Każde żądanie aktualizuje `last_seen_at` poprzez `update_session_activity`, co umożliwia audyty oraz narzuca maksymalny okres bezczynności.

---

## 6. Konfiguracja i uruchomienie

### 6.1. Zależności środowiskowe

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r proxy/requirements.txt
```

Kluczowe biblioteki: `psycopg2-binary`, `argon2-cffi`, `cryptography`, `python-dotenv`, `pyotp`, `qrcode[pil]`.

### 6.2. Parametry środowiskowe (wycinek)

| Zmienna | Domyślna wartość | Znaczenie |
| --- | --- | --- |
| `ROOT_DOMAIN` | `ppowicz.pl` | Walidacja hosta i generowanie URL-i powrotnych. |
| `PROJECTS_ROOT` | `/home/ppowicz/projects` | Lokalizacja plików `proxy-config.json`. |
| `SESSION_COOKIE_DOMAIN` | `.ppowicz.pl` | Zakres ciasteczek sesyjnych. |
| `PROXY_AUTH_TOKEN_KEY` | – | Klucz HMAC (32 bajty) do podpisywania `proxy_auth`. |
| `TOTP_SECRET_KEY` | – | Klucz Fernet do szyfrowania sekretów TOTP. |
| `LOG_RETENTION_DAYS` | `90` | Retencja logów w plikach i bazie. |
| `SCAN_INTERVAL_SECONDS` | `5` | Kadencja ponownego wczytania konfiguracji projektów. |

Pełną listę należy analizować w `proxy/proxy.py` i `proxy/db.py`.

### 6.3. Start serwera

```bash
python3 proxy/proxy.py
```

Domyślne nasłuchiwanie: `0.0.0.0:443` z certyfikatami Let’s Encrypt (`/etc/letsencrypt/live/ppowicz.pl/...`).

---

## 7. Interfejs administracyjny i API

- **UI**: `https://admin.ppowicz.pl/` – wymaga uwierzytelnionej sesji admina (`user_is_admin`). Szablony w `proxy/sites/admin_*.html` prezentują statystyki systemowe, logi, użytkowników, role, projekty.
- **API JSON**: przestrzeń `/api/` zapewnia operacje na logach (`/api/logs`, `/api/logs/analytics`, `/api/logs/delete`), użytkownikach (`/api/users/...`), rolach i uprawnieniach, a także moduł statusu projektów oraz metryki (`/api/dashboard/metrics`). Każdy endpoint zwraca `{"ok": true}` lub struktury błędowe i wymaga ważnych ciasteczek sesyjnych.
- **Audyt**: wszystkie wywołania admina reużywają mechanizmu logowania HTTP oraz wpisów w bazie, co pozwala korelować zmiany z tożsamościami.

### 7.1. Struktura API

| Obszar | Endpointy | Opis |
| --- | --- | --- |
| **Metryki i stan** | `GET /api/dashboard/metrics` | Zwraca snapshot CPU/RAM/dysku, uptime, zdrowie DB, liczbę projektów, statystyki ruchu. |
| **Status projektów** | `GET /api/projects/status` | Pinguje każdy skonfigurowany projekt lokalny i raportuje status, czas odpowiedzi, ewentualne błędy. |
| **Logi HTTP** | `GET /api/logs?limit=N`<br>`GET /api/logs/analytics`<br>`POST /api/logs/delete` | Przegląd ostatnich logów (sanetyzowanych), agregaty (timeline, top paths, error rate) oraz usuwanie wskazanych wpisów (`{"log_ids": [...]}`). |
| **Eksplorator DB** | `GET /api/db/tables`<br>`GET /api/db/<table>?limit=N`<br>`POST /api/db/<table>/update` | Lista tabel, podgląd kolumn i rekordów oraz aktualizacja pojedynczej komórki (podanie klucza głównego i nowej wartości). |
| **Użytkownicy** | `GET /api/users`<br>`POST /api/users/update`<br>`POST /api/users/assign_role`<br>`POST /api/users/deassign_role`<br>`POST /api/users/<id>/roles`<br>`POST /api/users/set_active`<br>`POST /api/users/delete`<br>`POST /api/users/disable-2fa` | Operacje na kontach: edycja pól, przypisywanie ról (pojedynczo lub hurtowo), aktywacja/deaktywacja, kasowanie, reset 2FA. |
| **Role i uprawnienia** | `GET /api/roles`<br>`POST /api/roles`<br>`POST /api/roles/<id>/update`<br>`GET /api/roles/<id>/permissions`<br>`POST /api/roles/<id>/permissions`<br>`GET /api/permissions`<br>`POST /api/permissions` | Tworzenie/modyfikacja ról i uprawnień oraz przypisywanie ich do ról. |

Uwagi wykonawcze:
- Wszystkie żądania `POST` przyjmują JSON (nagłówek `Content-Type: application/json`).
- Odpowiedzi sukcesu mają strukturę `{"ok": true}` lub zawierają dane; błędy zwracają `{"error": "..."}` wraz ze statusem 4xx/5xx.
- API opiera się na tej samej sesji co panel – nie przewidziano tokenów osobnych; CSRF jest mitigowany przez SameSite ciasteczek i brak formularzy publicznych.

---

## 8. Mechanizmy obserwowalności i bezpieczeństwa operacyjnego

- **Sanetyzacja danych w logach** – nagłówki wrażliwe (`Authorization`, `Cookie` itd.) zastępowane są znacznikiem `<redacted>`, analogicznie całe ciała żądań wykrytych jako formularze/login.
- **Retencja i rotacja** – plik `proxy.log` podlega przycinaniu (funkcja `cleanup_log_file`), a tabela `http_logs` oczyszczana jest cyklicznie (`cleanup_http_logs_older_than`).
- **Limity ruchu** – zaimplementowany jest własny limiter opary na `collections.deque`, dzięki czemu logowania, rejestracje i akcje 2FA są odporne na brute-force.
- **Monitor zasobów** – `GET /api/dashboard/metrics` agreguje obciążenie CPU, pamięci, dysku oraz kondycję DB, co umożliwia operatorom szybkie wykrywanie anomalii.
- **Odporność na awarie backendów** – błędy w komunikacji z projektem są raportowane jako 502 i natychmiast logowane wraz z informacją diagnostyczną.

---

## 9. Dalsze usprawnienia (kierunki badawcze)

1. Wprowadzenie CSRF tokenów dla formularzy i API w panelu admina.
2. Konfiguracja nagłówków bezpieczeństwa (CSP, HSTS, Referrer-Policy) w każdej ścieżce odpowiedzi.
3. Delegacja funkcji proxy do dedykowanego modułu (`ProjectProxy`) w celu dalszej modularizacji oraz łatwiejszego testowania jednostkowego.
4. Automatyzacja odświeżania certyfikatów LE (hook po `certbot renew`).
