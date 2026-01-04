# T-Pot do AbuseIPDB
[![License: GPL v3](https://img.shields.io/github/license/sefinek/T-Pot-To-AbuseIPDB)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/github/package-json/v/sefinek/T-Pot-To-AbuseIPDB?label=version)](https://github.com/sefinek/T-Pot-To-AbuseIPDB)
[![Node.js](https://img.shields.io/github/package-json/engines/node/sefinek/T-Pot-To-AbuseIPDB?logo=node.js&logoColor=white&color=339933)](https://nodejs.org)
[![Last Commit](https://img.shields.io/github/last-commit/sefinek/T-Pot-To-AbuseIPDB?label=last%20commit)](https://github.com/sefinek/T-Pot-To-AbuseIPDB/commits)

Automatyczny system raportowania złośliwych aktywności wykrytych przez honeypoty T-Pot do bazy danych AbuseIPDB.
Skrypt monitoruje logi z różnych honeypotów, analizuje próby ataków i automatycznie zgłasza je.


## 🎯 Główne funkcje
1. ✅ Inteligentne raportowanie z cooldown minimum 15 minut zapobiega duplikatom
2. ✅ Skrypt automatycznie przypisuje kategorie nadużyć na podstawie typu ataku
3. ✅ Pełne wsparcie dla raportowania zbiorczego po osiągnięciu limitu API
4. ✅ Ochrona przed przepełnieniem bufora
5. ✅ Automatyczne ponawianie nieudanych żądań
6. ✅ Pełne wsparcie dla IPv4 oraz IPv6
7. ✅ Pomijanie ruchu UDP oraz lokalnych adresów IP
8. ✅ Opcjonalne powiadomienia Discord z alertami i dziennymi statystykami
9. ✅ Opcjonalne zapisywanie historii aktywności IP do plików
10. ✅ Automatyczne aktualizacje przez Git z harmonogramem cron
11. ✅ Cykliczne sprawdzanie dynamicznego IP, które zapobiegnie auto-raportowaniu
12. ✅ Automatyczne sprawdzanie najnowszej wersji repozytorium i powiadamianie o nowych wersjach
13. ✅ Gotowa konfiguracja produkcyjna dla PM2


## 🐝 Obsługiwane honeypoty (więcej wkrótce)
- COWRIE
- DIONAEA
- HONEYTRAP

> [!NOTE]
> Skrypt automatycznie pomija ruch UDP (zgodnie z zasadami AbuseIPDB) oraz adresy IP specjalnego przeznaczenia (localhost, prywatne, link-local, multicast).

> [!NOTE]
> Repozytorium jest w fazie beta i wciąż jest rozwijane. Zachęcam do robienia Pull Requestów i zgłaszania problemów!


## 💬 Wsparcie i społeczność
Masz jakieś problemy, pytania lub po prostu chcesz otrzymywać powiadomienia o ważnych zmianach i nowych funkcjach?
- 💬 Dołącz do mojego [serwera Discord](https://discord.gg/S7NDzCzQTg)!
- 🐛 Nie korzystasz z Discorda? Możesz otworzyć [issue na GitHubie](https://github.com/sefinek/T-Pot-To-AbuseIPDB/issues)


## 📦 Wymagania systemowe
- **Node.js** w wersji **20.x lub nowszej** (sprawdź: `node -v`)
- **npm** w wersji **11.x lub nowszej** (sprawdź: `npm -v`)
- **Git** (zalecana najnowsza wersja)
- **T-Pot** - zainstalowany i działający honeypot
- Dostęp do logów T-Pot (domyślnie w `~/tpotce/data/`)

### Wymagane usługi
- **Konto AbuseIPDB** - zarejestruj się na [AbuseIPDB.com](https://www.abuseipdb.com/register)
- **Klucz API AbuseIPDB** - uzyskaj z [panelu API](https://www.abuseipdb.com/account/api)
- **(Opcjonalnie)** Discord webhook dla powiadomień o atakach i błędach

> [!NOTE]
> AbuseIPDB posiada dzienne limity raportowania. Po osiągnięciu limitu skrypt automatycznie przełącza się na tryb buforowania i wysyła raporty zbiorcze następnego dnia.


## 🚀 Instalacja i konfiguracja
### 1. Instalacja Node.js i npm
Jeśli nie masz zainstalowanego Node.js, skorzystaj z poniższego skryptu:
- 📘 [Instalacja Node.js i npm](https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649)

Opcjonalnie możesz zaktualizować Git do najnowszej wersji:
- 📘 [Aktualizacja Git](https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada)

### 2. Klonowanie repozytorium
```bash
git clone --recurse-submodules https://github.com/sefinek/T-Pot-To-AbuseIPDB.git
```

> [!IMPORTANT]
> Flaga `--recurse-submodules` jest wymagana do pobrania wszystkich zależności projektu.

### 3. Instalacja zależności npm
```bash
cd T-Pot-To-AbuseIPDB
npm install
```

### 4. Konfiguracja
Skopiuj domyślny plik konfiguracyjny i dostosuj go do swoich potrzeb:

```bash
cp config.default.js config.js
```

Następnie edytuj plik `config.js` i skonfiguruj następujące opcje:

#### 🔑 Wymagane ustawienia

> [!IMPORTANT]
> Musisz uzyskać klucz API z [AbuseIPDB](https://www.abuseipdb.com/account/api). Bez niego skrypt nie będzie działać.

```javascript
ABUSEIPDB_API_KEY: 'twój-klucz-api' // Uzyskaj z https://www.abuseipdb.com/account/api
```

#### 🖥️ Ustawienia serwera
```javascript
SERVER_ID: 'pl-waw-honeypot',        // Identyfikator twojego honeypota (np. 'pl-waw-honeypot', 'home-honeypot')
EXTENDED_LOGS: false,                // Szczegółowe logowanie (może się przydać do debugowania ewentualnych problemów)
```

#### 📁 Ścieżki do logów
Dostosuj ścieżki, jeśli T-Pot jest zainstalowany w innej lokalizacji:

```javascript
COWRIE_LOG_FILE: '~/tpotce/data/cowrie/log/cowrie.json',
DIONAEA_LOG_FILE: '~/tpotce/data/dionaea/log/dionaea.json',
HONEYTRAP_LOG_FILE: '~/tpotce/data/honeytrap/log/attackers.json',
```

#### 🌐 Ustawienia sieci
```javascript
IP_ASSIGNMENT: 'dynamic',             // 'static' lub 'dynamic'
IP_REFRESH_SCHEDULE: '0 */6 * * *',   // Sprawdzanie IP co 6 godzin (dla dynamic)
IPv6_SUPPORT: true                    // Włącz, jeśli masz publiczny IPv6
```

#### ⏱️ Zarządzanie raportami
```javascript
IP_REPORT_COOLDOWN: 6 * 60 * 60 * 1000, // Czas między raportami tego samego IP (domyślnie 6 godzin)
                                         // UWAGA: Minimum to 15 minut (900000 ms) - wymóg AbuseIPDB
```

> [!IMPORTANT]
> **Raportowanie zbiorcze:** Gdy osiągniesz dzienny limit raportowania, skrypt automatycznie:
> 1. Przełączy się w tryb buforowania
> 2. Zbiera nadchodzące IP-y w pamięci (maksymalnie 100,000)
> 3. Zapisuje bufor do pliku po każdym dodaniu
> 4. Następnego dnia (00:01 UTC) automatycznie wysyła wszystkie zebrane IP-y w formacie CSV
> 5. Bufor jest dzielony na mniejsze pakiety jeśli przekracza limity API

#### 📝 Historia IP (opcjonalnie)
```javascript
LOG_IP_HISTORY_ENABLED: false,        // Włącz zapisywanie historii
LOG_IP_HISTORY_DIR: './data'          // Katalog dla historii IP
```

#### 🔔 Discord webhooks (opcjonalnie)
```javascript
DISCORD_WEBHOOK_ENABLED: false,
DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/...',
DISCORD_WEBHOOK_USERNAME: 'SERVER_ID',  // Nazwa wyświetlana jako autor (użyj 'SERVER_ID' dla automatycznej nazwy)
DISCORD_USER_ID: 'twój-discord-id'      // Otrzymasz wzmianki (@mention) w ważnych zdarzeniach
```

**Funkcje Discord:**
- 📊 **Dzienne podsumowania** - automatycznie generowane statystyki ataków wysyłane codziennie
- 🚨 **Powiadomienia o błędach** - natychmiastowe alerty o krytycznych problemach
- ✅ **Potwierdzenia startu** - powiadomienie gdy skrypt uruchomi się pomyślnie
- 🔄 **Informacje o aktualizacjach** - powiadomienia o nowych wersjach
- ⚡ **Rate limiting** - max 3 wiadomości co 3 sekundy (ochrona przed banem Discord)

#### 🔄 Automatyczne aktualizacje

> [!WARNING]
> Nie są one zalecane ze względu na potencjalne problemy z kompatybilnością. Włącz tę funkcję, tylko jeśli aktywnie monitorujesz serwer i jesteś gotowy na interwencję w przypadku problemów.

```javascript
AUTO_UPDATE_ENABLED: false,              // Włącz tylko jeśli aktywnie monitorujesz serwer
AUTO_UPDATE_SCHEDULE: '0 14,16,20 * * *' // Harmonogram aktualizacji
```

### 5. Pierwsze uruchomienie do testów
```bash
node .
```

#### Uruchomienie w trybie produkcyjnym z PM2
PM2 to menedżer procesów Node.js, który pozwala na uruchomienie skryptu w tle i automatyczne ponowne uruchomienie w przypadku awarii.
To repozytorium zawiera już gotową konfigurację ekosystemu PM2, więc nie musisz niczego więcej robić. 😉

**Instalacja PM2:**
```bash
npm install pm2 -g
```

**Uruchomienie:**
```bash
pm2 start
```

> [!TIP]
> Skrypt automatycznie wczyta konfigurację z pliku `ecosystem.config.js`.

**Dodanie do autostartu systemu:**
```bash
eval "$(pm2 startup | grep sudo)"
```

**Przydatne komendy PM2:**
```bash
pm2 logs                   # Wyświetl logi wszystkich procesów w czasie rzeczywistym
pm2 logs tpot-abuseipdb    # Wyświetl logi tylko tego skryptu
pm2 list                   # Status wszystkich uruchomionych procesów
pm2 restart tpot-abuseipdb # Restart skryptu
pm2 stop tpot-abuseipdb    # Zatrzymaj skrypt
pm2 delete tpot-abuseipdb  # Usuń skrypt z PM2
pm2 monit                  # Monitoring procesów w czasie rzeczywistym
pm2 flush                  # Wyczyść wszystkie logi
```

### 6. Aktualizacja projektu
Aby zaktualizować projekt do najnowszej wersji, uruchom:
```bash
npm run update
```

Skrypt automatycznie:
- Pobierze najnowsze zmiany z repozytorium Git
- Zaktualizuje submoduły
- Zainstaluje zależności
- Zrestartuje proces PM2


## 📊 Przykładowe raporty
Poniżej znajdziesz przykłady raportów generowanych przez skrypt na podstawie różnych typów ataków.

### Atak brute-force na SSH
```text
Honeypot hit: Brute-force attack detected on 22/SSH
• Credentials used: support:support, ubnt:ubnt, usario:usario, user:user, admin:admin
• Number of login attempts: 5
• Client: SSH-2.0-libssh_0.11.1
```

### Nieautoryzowany ruch sieciowy
```text
Honeypot hit: Unauthorized traffic (243 bytes of payload); 20443 [3] TCP
```

### Próba połączenia bez payload (skanowanie)
```text
Honeypot hit: Empty payload (likely service probe); 1028 [1] TCP
```

### Próba połączenia TELNET
```text
Honeypot hit: Unauthorized connection attempt detected on 23/TELNET
```

### Żądanie HTTP
```text
Honeypot hit: HTTP/1.1 request on 8800

GET /
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: identity; 8800 [2] TCP
```

### Próba wykorzystania jako proxy
```text
Honeypot hit: HTTP/1.1 request on 13261

CONNECT myip.wtf:443
User-Agent: Go-http-client/1.1; 13261 [2] TCP
```


## 🤝 Współtworzenie
Wkład w rozwój projektu jest mile widziany!


## 📄 Licencja
Ten projekt jest licencjonowany na podstawie licencji GNU General Public License v3.0 - szczegóły w pliku [LICENSE](LICENSE).


## 👤 Kontakt
- Website: [sefinek.net](https://sefinek.net)
- Email: [contact@sefinek.net](mailto:contact@sefinek.net)
- GitHub: [@sefinek](https://github.com/sefinek)


## ⭐ Podziękowania
Jeśli ten projekt okazał się dla Ciebie przydatny, rozważ oznaczenie go gwiazdką na GitHubie! Zdecydowanie zmotywuje mnie to do dalszego rozwoju.


---

> [!CAUTION]
> Używaj tego narzędzia odpowiedzialnie i zgodnie z warunkami korzystania z AbuseIPDB oraz lokalnymi przepisami prawa.
