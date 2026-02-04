📌 Project Overview

The Log Analyzer Intrusion Detection System monitors HTTP access logs to identify repeated failed authentication attempts (HTTP 401 responses).
It applies time-window based correlation to detect brute-force attacks, classifies attack severity, and generates visual and textual incident reports through an intuitive GUI.

This project demonstrates the practical application of cybersecurity concepts, log analysis, and Python GUI development.

🚀 Features

📄 Access log parsing (.log files)

🔐 Brute-force attack detection

⏱️ Time-window based correlation analysis

🚨 Severity classification (LOW / MEDIUM / HIGH)

📝 Automated incident report generation

📊 Graphical visualization of attack traffic

🖥️ User-friendly Tkinter GUI

✅ Whitelist IP support to reduce false positives

🛠️ Technologies Used

Python 3

Tkinter – GUI development

Pandas – Log data processing

Matplotlib – Attack visualization

Datetime – Time-based correlation

📂 Project Structure
Log-Analyzer-IDS/
│
├── main.py                  # Main application script
├── incident_report.txt      # Generated intrusion report
├── attack_visual.png        # Attack visualization graph
├── sample_logs/
│   └── access.log           # Sample log file
├── README.md                # Project documentation
└── requirements.txt         # Required Python libraries

⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/your-username/Log-Analyzer-IDS.git
cd Log-Analyzer-IDS

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run the Application
python main.py

🖥️ How It Works

User selects a server access log file via the GUI

System filters failed login attempts (HTTP 401)

Applies time-window correlation to detect attack patterns

Classifies attack severity

Generates:

📄 Incident report (incident_report.txt)

📊 Attack traffic graph (attack_visual.png)

Displays alerts in the GUI

📊 **Sample Output**

Incident Report: Text-based alert summary with IP addresses and attempt count

Graph: Bar chart showing failed login attempts per IP

GUI Alerts: Real-time alert display inside the application

🔐 **Security Concepts Demonstrated**

Brute-force attack detection

Log-based intrusion detection

Correlation analysis

False-positive reduction using IP whitelisting

📌 **Future Enhancements**

🔄 Real-time log monitoring

📡 Email / Telegram alert integration

🧠 Machine-learning based anomaly detection

📈 Dashboard-based visualization

🌐 Support for multiple log formats

📜 **License**

This project is licensed under the MIT License – free to use, modify, and distribute.

🙌 **Acknowledgements**

Inspired by real-world SIEM and Intrusion Detection Systems used in cybersecurity operations.
