# PSTCentral

LAN PST Backup System

📌 Overview

LAN PST Backup System is a PowerShell-based project designed to collect and back up Microsoft Outlook PST files from multiple Windows systems over a LAN.

The system uses Windows network access (SMB) with system username, password, and IP address to remotely access machines and copy PST files to a central backup location.

This solution is ideal for:
	•	IT administrators
	•	Enterprise email backup
	•	Centralized Outlook data collection
	•	Compliance and archiving purposes

⸻

🛠️ Technology Stack
	•	PowerShell
	•	Windows SMB / Administrative Access
	•	LAN Network (TCP/IP)
	•	Windows Authentication (Username & Password)

⸻

⚙️ How It Works
	1.	The script connects to remote systems using:
	•	System IP address
	•	Windows username
	•	Windows password
	2.	It accesses common Outlook PST locations such as:
	•	C:\Users\<username>\Documents\Outlook Files
	•	C:\Users\<username>\AppData\Local\Microsoft\Outlook
	3.	All .pst files are copied over the LAN
	4.	Files are stored in a central backup directory, organized by:
	•	Computer name
	•	Username
	•	Date/time (optional)

⸻

📂 Project Structure

lan-pst-backup/
│
├── scripts/
│   ├── backup-pst.ps1
│   ├── connect-remote.ps1
│   └── config.ps1
│
├── logs/
│   └── backup-log.txt
│
├── backups/
│   └── <computer-name>/<username>/
│
└── README.md


⸻

🔐 Requirements
	•	Windows OS (Client & Server)
	•	PowerShell 5.1 or later
	•	Network connectivity between systems
	•	Administrative access to target machines
	•	File sharing enabled on remote systems
	•	Firewall allows SMB (Port 445)

⸻

▶️ Usage
	1.	Clone the repository:

git clone https://github.com/ipraveenkohli/PSTCentral.git


	2.	Edit the configuration file:
	•	Target system IPs
	•	User credentials
	•	Backup destination path
	3.	Run PowerShell as Administrator
	4.	Execute the script:

.\backup-pst.ps1



⸻

🧾 Features
	•	Centralized PST backup
	•	LAN-based file copying
	•	Credential-based authentication
	•	Multiple system support
	•	Logging for audit and troubleshooting
	•	Automatic folder organization

⸻

⚠️ Security Notes
	•	Credentials should be handled securely
	•	Avoid hardcoding passwords in scripts
	•	Use encrypted credential storage where possible
	•	Limit access to backup directories

⸻

🚧 Limitations
	•	Windows-only solution
	•	Requires admin-level permissions
	•	Outlook must not be actively locking PST files
	•	Large PST files may take time over LAN

⸻

📈 Future Enhancements
	•	Encrypted backups
	•	Credential vault integration
	•	Scheduler support
	•	Incremental backups
	•	GUI wrapper
	•	Error retry mechanism

⸻

📜 Disclaimer

This project is intended for authorized administrative use only.
Ensure you have proper permission before accessing or copying user data.

