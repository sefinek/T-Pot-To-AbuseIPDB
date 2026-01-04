# T-Pot to AbuseIPDB
[![License: GPL v3](https://img.shields.io/github/license/sefinek/T-Pot-To-AbuseIPDB)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/github/package-json/v/sefinek/T-Pot-To-AbuseIPDB?label=version)](https://github.com/sefinek/T-Pot-To-AbuseIPDB)
[![Node.js](https://img.shields.io/github/package-json/engines/node/sefinek/T-Pot-To-AbuseIPDB?logo=node.js\&logoColor=white\&color=339933)](https://nodejs.org)
[![Last Commit](https://img.shields.io/github/last-commit/sefinek/T-Pot-To-AbuseIPDB?label=last%20commit)](https://github.com/sefinek/T-Pot-To-AbuseIPDB/commits)

Integration with AbuseIPDB that enables automatic reporting of malicious activity detected by T-Pot honeypots.
The script monitors logs, analyzes attack attempts, and reports them automatically.

If you found this project useful, consider giving it a star! It will greatly motivate me to continue its development.


## 🎯 Key Features
✅ Support for **Cowrie**, **Dionaea**, and **Honeytrap** honeypots (more planned).  
✅ Intelligent reporting mechanism with a minimum **15-minute cooldown**, effectively eliminating duplicate reports.  
✅ Automatic assignment of abuse categories based on the detected attack type.  
✅ Full support for bulk reporting when API limits are reached.  
✅ Protection mechanisms against buffer overflow and data loss.  
✅ Automatic retry of failed API requests.  
✅ Full support for **IPv4** and **IPv6** addresses.  
✅ Automatic skipping of **UDP** traffic and special-purpose IP addresses (`local`, `private`, `multicast`).  
✅ Optional **Discord** notifications with attack alerts and daily statistics.  
✅ Optional logging of IP activity history to files.  
✅ Automatic project updates via **Git** using a **cron** schedule.  
✅ Periodic public IP address checks to prevent self-reporting.  
✅ Automatic detection of new repository versions with update notifications.  
✅ Ready-to-use production configuration for **PM2**.

> [!NOTE]
> The script automatically skips UDP traffic (in accordance with AbuseIPDB rules) and special-purpose IP addresses (localhost, private, link-local, multicast).

> [!NOTE]
> The repository is actively developed. Feel free to report [Issues](https://github.com/sefinek/T-Pot-To-AbuseIPDB/issues) and submit [Pull requests](https://github.com/sefinek/T-Pot-To-AbuseIPDB/pulls)!


## 💬 Support and Community
Do you have any issues, questions, or just want to receive notifications about important changes and new features?

💬 Join my [Discord server](https://discord.gg/S7NDzCzQTg)!  
🐛 Not using Discord? You can open an [issue on GitHub](https://github.com/sefinek/T-Pot-To-AbuseIPDB/issues).


## 📦 System Requirements
* **Node.js** version **20.x or newer** (check with: `node -v`)
* **npm** version **11.x or newer** (check with: `npm -v`)
* **Git** (latest version recommended)
* **T-Pot** (installed and properly working honeypot)
* **AbuseIPDB API key** ([click to obtain](https://www.abuseipdb.com/account/api))
* **Discord webhook** (for attack and error notifications, optional)
* **Access to T-Pot logs** (default location: `~/tpotce/data/`)

> [!NOTE]
> If the daily API limit is reached, the script automatically switches to buffering mode and sends a bulk report the next day.


## 🚀 Installation and Configuration

### 1. Installing Node.js & Git
If you don't have Node.js installed, [click here](https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649).
If you don't have Git installed, [click here](https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada).

### 2. Cloning the Repository
```bash
git clone --recurse-submodules https://github.com/sefinek/T-Pot-To-AbuseIPDB.git
```

> [!IMPORTANT]
> The `--recurse-submodules` flag is required to properly fetch the [sefinek/IPDB-Integration-Scripts](https://github.com/sefinek/IPDB-Integration-Scripts) submodule.

### 3. Installing npm Dependencies
```bash
cd T-Pot-To-AbuseIPDB
npm install
```

### 4. Configuration
Copy the default configuration file and adjust it to your needs:

```bash
cp config.default.js config.js
```

Then open `config.js` in your favorite text editor (e.g. `mcedit`, `nano`) and configure the options below:

#### 🔑 Required Settings
> [!IMPORTANT]
> You must obtain an API key from [AbuseIPDB](https://www.abuseipdb.com/account/api). Without it, the script will not work.

```js
ABUSEIPDB_API_KEY: 'your-api-key'  // Obtain from https://www.abuseipdb.com/account/api
```

#### 🖥️ Server Settings
```js
SERVER_ID: 'pl-waw-honeypot',  // Your honeypot identifier (e.g. 'pl-waw-honeypot', 'home-honeypot')
EXTENDED_LOGS: false           // Verbose logging (useful for debugging)
```

#### 📁 Log Paths
Adjust the paths if T-Pot is installed in a different location:

```js
COWRIE_LOG_FILE: '~/tpotce/data/cowrie/log/cowrie.json',
DIONAEA_LOG_FILE: '~/tpotce/data/dionaea/log/dionaea.json',
HONEYTRAP_LOG_FILE: '~/tpotce/data/honeytrap/log/attackers.json'
```

#### 🌐 Network Settings
```js
IP_ASSIGNMENT: 'dynamic',            // 'static' or 'dynamic'
IP_REFRESH_SCHEDULE: '0 */6 * * *',  // IP check every 6 hours
IPv6_SUPPORT: true                   // true if your ISP provides IPv6
```

#### ⏱️ Report Management
```js
IP_REPORT_COOLDOWN: 6 * 60 * 60 * 1000 // Time between reports for the same IP (default: 6 hours)
                                       // NOTE: Minimum is 15 minutes (900000 ms) – AbuseIPDB requirement
```

> [!IMPORTANT]
> If the daily reporting limit is reached, the script automatically switches to buffering mode,
> collects new IP addresses, and submits them in bulk the next day in compliance with AbuseIPDB API limits.

#### 📝 IP History (Optional)
```js
LOG_IP_HISTORY_ENABLED: false,  // Enable history logging
LOG_IP_HISTORY_DIR: './data'    // Directory for IP history
```

#### 🔔 Discord Webhooks (Optional)
```js
DISCORD_WEBHOOK_ENABLED: false,
DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/...',
DISCORD_WEBHOOK_USERNAME: 'SERVER_ID',  // Display name (use 'SERVER_ID' for automatic naming)
DISCORD_USER_ID: 'your-discord-id'      // You will receive mentions (@mention) on important events
```

📊 **Daily summaries**: automatically generated daily attack statistics  
🚨 **Error notifications**: instant alerts for critical issues  
✅ **Startup confirmations**: notification when the script starts successfully  
🔄 **Update notifications**: alerts about new versions  
⚡ **Rate limiting**: max 3 messages per 3 seconds

#### 🔄 Automatic Updates
```js
AUTO_UPDATE_ENABLED: false,               // Enable only if you actively monitor the server
AUTO_UPDATE_SCHEDULE: '0 14,16,20 * * *'  // Update schedule
```

> [!WARNING]
> Not recommended due to potential compatibility issues. Enable only if you actively monitor the server and are ready to intervene if problems occur.

### 5. First Test Run
```bash
node .
```

#### Running in Production Mode with PM2
PM2 is a Node.js process manager that allows the script to run in the background and automatically restart on failure.
This repository already includes a ready-to-use PM2 ecosystem configuration, so no additional setup is required. 😉

**Install PM2:**
```bash
npm install pm2 -g
```

**Start:**
```bash
pm2 start
```

> [!TIP]
> The script automatically loads the configuration from `ecosystem.config.js`.

**Add to system startup:**
```bash
eval "$(pm2 startup | grep sudo)"
```

**Useful PM2 Commands:**
```bash
pm2 logs                   # Show logs of all processes in real time
pm2 logs tpot-abuseipdb    # Show logs only for this script
pm2 list                   # Status of all running processes
pm2 restart tpot-abuseipdb # Restart the script
pm2 stop tpot-abuseipdb    # Stop the script
pm2 delete tpot-abuseipdb  # Remove the script from PM2
pm2 monit                  # Real-time process monitoring
pm2 flush                  # Clear all logs
```

### 6. Project Update
To update the project to the latest version, run:
```bash
npm run update
```

The script will automatically:
* fetch the latest changes from the Git repository,
* update submodules,
* update required npm dependencies,
* restart the PM2 process.

After the update, check `pm2 logs` to ensure everything is working correctly.


## 📊 Example Reports
Below are examples of reports generated by the script based on different attack types.

### SSH Brute-Force Attack
```text
Honeypot hit: Brute-force attack detected on 22/SSH
• Credentials used: support:support, ubnt:ubnt, usario:usario, user:user, admin:admin
• Number of login attempts: 5
• Client: SSH-2.0-libssh_0.11.1
```

### Unauthorized Network Traffic
```text
Honeypot hit: Unauthorized traffic (243 bytes of payload); 20443 [3] TCP
```

### Connection Attempt Without Payload (Scanning)
```text
Honeypot hit: Empty payload (likely service probe); 1028 [1] TCP
```

### TELNET Connection Attempt
```text
Honeypot hit: Unauthorized connection attempt detected on 23/TELNET
```

### HTTP Request
```text
Honeypot hit: HTTP/1.1 request on 8800

GET /
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: identity; 8800 [2] TCP
```

### Proxy Abuse Attempt

```text
Honeypot hit: HTTP/1.1 request on 13261

CONNECT myip.wtf:443
User-Agent: Go-http-client/1.1; 13261 [2] TCP
```


## 📄 License
This project is licensed under the GNU General Public License v3.0 – see the [LICENSE](LICENSE) file for details.

---

> [!CAUTION]
> Use this tool responsibly and in accordance with the AbuseIPDB terms of service and local laws.
