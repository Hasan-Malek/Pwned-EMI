# Pwned EMI v2.0 - Enhanced Edition 📱💻
![s1](https://github.com/user-attachments/assets/8d2c5d2b-c5cf-4cda-8795-cece9555f1a6)

**Pwned EMI v2.0** is a slick C-based tool to bypass EMI-locked Android phones for data transfer using a WiFi FTP APK! 📂🚀  
Install the WiFi FTP APK on your phone, connect your phone and PC via a mobile or PC hotspot, and let this tool scan your network to download files effortlessly.  
With recursive downloading, FTP fingerprinting, and colorful output, it’s perfect for ethical data recovery! 😎

> ⚠️ **Disclaimer:**  
Use this tool **ethically**! Only for devices you own or have **explicit permission** to access.  
Misuse may violate laws or terms of service. The author isn’t responsible for misuse! 😇

---

## 📋 Table of Contents

- [How It Works](#how-it-works-)
- [Installation](#installation-)
- [Usage](#usage-)
- [Screenshot](#screenshot-)
- [Contributing](#contributing-)
- [License](#license-)
- [Contact](#contact-)

---

## 🔍 How It Works

1. **Get the WiFi FTP APK**  
   Install a WiFi FTP app (e.g., _“WiFi FTP Server”_ from Google Play) on your Android phone. 📲

2. **Connect Phone and PC**  
   - **Mobile Hotspot 🌐**: Turn on your phone’s hotspot and connect your PC to it.  
   - **PC Hotspot 💻**: Turn on your PC’s hotspot and connect your phone to it.

3. **Start FTP Server**  
   Open the WiFi FTP APK, tap “Start” to launch the FTP server, and note the IP/port (e.g., `ftp://192.168.x.x:2221`). 🖥️

4. **Run Pwned EMI**  
   Use this tool on your PC to find the phone’s FTP server and download files. ⬇️

---

## 💾 Installation

### 🔧 Compile the Tool

```bash
gcc -o pwned_emi PwnedEmi.c
```

## 🚀 Run It
```bash
./pwned_emi
```

## 🚀 Usage
**✅ Set Up Network and APK**
  - Connect your phone and PC (mobile or PC hotspot).
  - Start the WiFi FTP APK and confirm the FTP server is running.
**🔧 Run Pwned EMI**
```bash
./pwned_emi
```
  - The tool scans your network for FTP servers (ports 2221, 21, 2121).
  - When it finds your phone’s FTP server:
      - It shows the server’s banner.
      - It lists files/directories.
   
## ⬇️ Download Files
If files or folders are found, it asks:
  ```bash
    Do you want to download all data? (y/n)
  ```
Enter y and specify a folder (e.g., /home/user/ftp_data).
The tool recursively downloads everything accessible!

## 📸 Screenshot
![s1](https://github.com/user-attachments/assets/464b73f4-bcd9-4104-bb19-865d2bea9560)

![s2](https://github.com/user-attachments/assets/94d9432b-aa96-4715-8873-53cf7b767f01)

![s3](https://github.com/user-attachments/assets/a9449225-0bb2-4d8c-8c02-883e4b0326d6)

## 📜 License
Licensed under the **MIT License**.

## 🌍 Connect with Me 
  - GitHub: [https://github.com/Hasan-Malek]
  - LinkedIn: [https://www.linkedin.com/in/hasan-malek-125036297/]

*Built for forensics experts and cybersecurity professionals! 🛡️💻*
