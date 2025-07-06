# Tricks with Trojan's v1.0 - Interactive Security Toolkit

![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Version](https://img.shields.io/badge/version-1.0-brightgreen.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)

**Tricks with Trojan's (TWT)** is an interactive system analysis and basic threat response toolkit for Windows systems, built on PowerShell. With its user-friendly text-based menu, it allows both novice and experienced users to quickly perform security checks on their systems.

*Created by: Emircan Akalın*

---

### Screenshot
*(You can add a screenshot of the console menu here. Replace the URL below after uploading.)*

![Tricks with Trojan's Menu](https://example.com/path/to/screenshot.png) 
*View of the main menu*

---

## 🚀 Features

* **Interactive Text-Based Menu:** A user-friendly interface for easy access to all modules.
* **HTML Reporting:** Consolidates all analysis results into a single, well-organized HTML file.
* **Secure Quarantine:** Safely moves suspicious files to a quarantine folder for later review instead of permanently deleting them.
* **Automatic Backups:** Automatically backs up registry keys before removing startup items.
* **Comprehensive Analysis Modules:**
    * Temporary file cleanup.
    * Optional (Quick/Full) Windows Defender scans.
    * Analysis and removal of startup programs.
    * Listing of active network connections with the option to terminate processes.
    * `hosts` file analysis to detect malicious redirections.
    * Scanning of Windows Event Logs for suspicious activities.
    * Detection of recently created suspicious files in user folders.

---

## 🛠️ Prerequisites

* **Operating System:** Windows 10 or later
* **PowerShell:** Version 5.1 or higher
* **Privileges:** The script must be **run as Administrator** for full functionality.

---

## ⚙️ Installation and Usage

1.  **Download the Script:** Download the `Tricks-With-Trojans.ps1` file (or your chosen `.ps1` file name) from this repository.
2.  **Open PowerShell as Administrator:**
    * Open the Start Menu and type "PowerShell".
    * Right-click on "Windows PowerShell" and select **"Run as administrator"**.
3.  **Navigate to the Script Directory:**
    * In the console, change the directory to the folder where you downloaded the file. For example:
        ```powershell
        cd C:\Users\YourUser\Downloads
        ```
4.  **Set Execution Policy (If Necessary):**
    * If you encounter an error while running the script, you may need to change the PowerShell execution policy. Run the following command to allow scripts for the current session only:
        ```powershell
        Set-ExecutionPolicy RemoteSigned -Scope Process
        ```
5.  **Run the Script:**
    ```powershell
    .\Tricks-With-Trojans.ps1
    ```
6.  Start using the tool by selecting an option from the menu.

---

## 📖 Modules Explained

* **1. Clear Temporary Files:** Deletes unnecessary files from the Windows and user TEMP folders.
* **2. Start Windows Defender Scan:** Provides options for a Quick or Full system scan.
* **3. Quarantine a File:** Moves a specified file to the secure quarantine folder.
* **4. Analyze Startup Items:** Scans the registry and startup folders, providing an option to remove suspicious entries.
* **5. Show Active Network Connections:** Lists connections in the `ESTABLISHED` state and the processes that created them, with an option to terminate the process.
* **6. Check Hosts File:** Reports any non-standard entries in the `hosts` file.
* **7. Scan Suspicious Event Logs:** Checks for events like new service installations or numerous failed logins.
* **8. Find Recent Suspicious Files:** Lists executables created within the last 7 days in critical user folders.
* **9. RUN ALL ANALYSES:** Sequentially runs all analysis modules (4-8) and creates a detailed HTML report on your Desktop.

---

## 📜 License

This project is licensed under the **[GNU General Public License v3.0](LICENSE)**. See the `LICENSE` file for more details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to open an issue to suggest features or create a pull request.

1.  Fork the Project.
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the Branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.
