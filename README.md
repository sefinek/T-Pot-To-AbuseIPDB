# T-Pot to AbuseIPDB (beta, not finished yet)
Do you have any questions or want to receive notifications about important changes or new features in my repositories?
Join my [Discord server](https://discord.gg/S7NDzCzQTg)! If you don't use Discord, you can also open an issue on GitHub.

## Supports
- ✅ COWIRE
- ✅ DIONAEA
- ✅ HONEYTRAP


## How to use
1. Install Node.js and npm, see: https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649.
   You may also want to update Git to the latest version: https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada

2. Clone this repository:
```bash
git clone --recurse-submodules https://github.com/sefinek/T-Pot-To-AbuseIPDB.git
```

3. Install dependencies
```bash
cd T-Pot-To-AbuseIPDB && npm install
```

4. Copy `config.default.js` to `config.js` and update it to fit your needs. Add AbuseIPDB API KEY!
```bash
cp config.default.js config.js
```

5. Manual startup
```bash
node .
```

6. If you want to run this script 24/7, use `pm2`. Check PM2 documentation for more information.
```bash
npm install pm2 -g
pm2 start
```

7. Add PM2 to startup:
```bash
pm2 startup
pm2 save
```

8. For log monitoring:
```bash
pm2 logs
```


## Example reports
```text
Honeypot hit: Brute-force attack detected on 22/SSH
• Credentials used: support:support, ubnt:ubnt, usario:usario, user:user, admin:admin
• Number of login attempts: 5
• Client: SSH-2.0-libssh_0.11.1
```

```text
Honeypot hit: Unauthorized traffic (243 bytes of payload); 20443 [3] TCP
```

```text
Honeypot hit: Empty payload (likely service probe); 1028 [1] TCP
```

```text
Honeypot hit: Unauthorized connection attempt detected on 23/TELNET
```

```text
Honeypot hit: HTTP/1.1 request on 8800

GET /
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: identity; 8800 [2] TCP
```

```text
Honeypot hit: HTTP/1.1 request on 13261

CONNECT myip.wtf:443
User-Agent: Go-http-client/1.1; 13261 [2] TCP
```


## Useful links
- https://www.abuseipdb.com/categories