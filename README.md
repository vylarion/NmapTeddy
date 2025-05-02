Here’s a clean, professional `README.md` for your **Nmap Teddy** project that reflects its functionality and ease of use:

---

# 🐻 Nmap Teddy

**Nmap Teddy** is a beginner-friendly yet powerful Python interface for [Nmap](https://nmap.org/), designed to simplify network reconnaissance with a visually pleasing command-line experience. Whether you're scanning ports, identifying systems, detecting vulnerabilities, or exploring network topology — Teddy has you covered.

> 🛡️ Made for developers, students, sysadmins, and curious tinkerers who want beautiful CLI scans without memorizing Nmap flags 🛡️

---

## ✨ Features

- 🔍 **Port Scan**  
  Scan top `N` ports and optionally detect services with version info.

- 🖥️ **System Detection**  
  Detect operating systems with accuracy and device type info.

- 🚨 **Vulnerability Identification**  
  Run powerful Nmap scripts to detect common vulnerabilities.

- 🛰️ **Network Topology**  
  Trace the route from your system to the target with TTL and RTT.

- 📄 **Export Results**  
  Save all outputs in structured `.txt` files with beautiful tables.

- 🎨 **Colorful CLI**  
  Clear, non-intrusive syntax-highlighted outputs using `colorama`.

---

## 🧰 Requirements

- Python 3.x  
- [Nmap](https://nmap.org/download.html) installed and accessible in your system path

### Python Packages

Install dependencies with:

```bash
pip install -r requirements.txt
```

**`requirements.txt`**
```txt
nmap
tabulate
colorama
pyfiglet
```

---

## 🚀 How to Use

Run the script:

```bash
python nmap_teddy.py
```

Follow the prompts to:

1. Enter a domain or IP (e.g., `example.com` or `192.168.0.1`)
2. Select a mode:
    - `1`: Port Scan
    - `2`: System Detection
    - `3`: Vulnerability Identification
    - `4`: Network Topology
3. View results in a structured table
4. Optionally save the output to a file

---

## 📸 Preview

```
  \  |                              __ __|          |      |
   \ |  __ `__ \    _` |  __ \         |   _ \   _` |   _` |  |   | 
 |\  |  |   |   |  (   |  |   |        |   __/  (   |  (   |  |   |
_| \_| _|  _|  _| \__,_|  .__/        _| \___| \__,_| \__,_| \__, | 
                          _|                                  ____/             

Enter the domain or IP address to scan:  scanme.nmap.org

Choose a functionality:
1. Port Scan
2. System Detection
3. Vulnerability Identification
4. Network Topology & Architecture

Enter choice (1/2/3/4):
```

---

## 📁 Output Sample

```txt
+--------+--------+-----------+----------------+----------+
| Port   | State  | Service   | Product        | Version  |
+--------+--------+-----------+----------------+----------+
| 22     | open   | ssh       | OpenSSH        | 7.6p1    |
| 80     | open   | http      | Apache httpd   | 2.4.29   |
+--------+--------+-----------+----------------+----------+
```

---

## 🔒 Legal & Usage Disclaimer

This tool is for **educational** and **authorized security testing** purposes only. Scanning systems without permission may be illegal.

---

## 📚 License

MIT License – Use freely, modify safely, share responsibly.
