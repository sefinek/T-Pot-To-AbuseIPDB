# T-Pot to AbuseIPDB (beta, not finished yet)
Do you have any questions or want to receive notifications about important changes or new features in my repositories?
Join my [Discord server](https://discord.gg/S7NDzCzQTg)! If you don't use Discord, you can also open an issue on GitHub.

## Supports
- ✅ COWIRE
- ✅ DIONAEA
- ✅ HONEYTRAP

## Clone
```bash
git clone --recurse-submodules https://github.com/sefinek/T-Pot-To-AbuseIPDB.git
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