Project Overview

This project presents a GUI-based Log Analyzer Intrusion Detection System that monitors server access logs to identify potential security threats such as suspicious login behavior and brute-force attacks.
The system analyzes HTTP access logs, detects repeated authentication failures (HTTP 401 responses), applies time-window correlation to assess attack patterns, and produces both visual and textual incident reports.

Key Features

✅ Server access log parsing (access.log)

✅ Brute-force login attempt detection

✅ Time-window based attack correlation

✅ Attack severity classification (LOW / MEDIUM / HIGH)

✅ Automated incident and alert report generation

✅ Graphical visualization of detected attacks

✅ User-friendly GUI built with Tkinter

✅ IP whitelist support to reduce false positives

Technologies Used

Python 3

Tkinter (Graphical User Interface)

Pandas (Log analysis & data processing)

Matplotlib (Data visualization)

Datetime module (Time-based correlation)