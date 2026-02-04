import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# ================== SETTINGS ==================
TRUSTED_IPS = ["127.0.0.1"]
WINDOW_MINUTES = 2

# ================== LOG PROCESSING ==================
def parse_access_log(file_path, limit):
    attack_entries = []

    try:
        with open(file_path, "r") as logfile:
            for line in logfile:
                tokens = line.split()

                if len(tokens) < 9:
                    continue

                client_ip = tokens[0]
                response_code = tokens[7]

                if client_ip in TRUSTED_IPS:
                    continue

                if response_code == "401":
                    raw_time = tokens[3].replace("[", "")
                    try:
                        event_time = datetime.strptime(
                            raw_time, "%d/%b/%Y:%H:%M:%S"
                        )
                        attack_entries.append((client_ip, event_time))
                    except ValueError:
                        pass
    except FileNotFoundError:
        return {}, None

    if not attack_entries:
        return {}, None

    log_df = pd.DataFrame(attack_entries, columns=["SourceIP", "Timestamp"])
    return detect_bruteforce(log_df, limit), log_df

# ================== DETECTION LOGIC ==================
def detect_bruteforce(df, limit):
    detected = {}

    for ip_addr in df["SourceIP"].unique():
        time_series = df[df["SourceIP"] == ip_addr]["Timestamp"].sort_values()

        for idx in range(len(time_series)):
            window_start = time_series.iloc[idx]
            window_end = window_start + pd.Timedelta(minutes=WINDOW_MINUTES)

            attempts = ((time_series >= window_start) & (time_series <= window_end)).sum()

            if attempts >= limit:
                detected[ip_addr] = attempts
                break

    return detected

# ================== REPORTING ==================
def write_incident_file(results):
    with open("incident_report.txt", "w") as report:
        report.write("INTRUSION DETECTION REPORT\n")
        report.write("---------------------------\n\n")

        for ip, hits in results.items():
            report.write(f"Source IP : {ip}\n")
            report.write(f"Failures  : {hits}\n")
            report.write("Risk      : HIGH\n\n")

# ================== VISUALIZATION ==================
def plot_results(results):
    if not results:
        return

    plt.figure(figsize=(7, 4))
    plt.bar(results.keys(), results.values())
    plt.xlabel("IP Address")
    plt.ylabel("Failed Login Attempts")
    plt.title("Detected Brute Force Activity")
    plt.tight_layout()
    plt.savefig("attack_visual.png")
    plt.show()

# ================== GUI HANDLERS ==================
def start_scan():
    path = selected_file.get()

    if not path:
        messagebox.showwarning("Missing File", "Please choose a log file.")
        return

    try:
        limit = int(threshold_input.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Threshold must be numeric.")
        return

    findings, dataframe = parse_access_log(path, limit)
    result_box.delete("1.0", tk.END)

    if not findings:
        result_box.insert(tk.END, "No suspicious activity detected.\n")
        return

    write_incident_file(findings)
    plot_results(findings)

    for ip, count in findings.items():
        result_box.insert(
            tk.END,
            f"[WARNING]\nIP Address: {ip}\nAttempts: {count}\n\n"
        )

def select_log_file():
    chosen = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
    )
    selected_file.set(chosen)

# ================== GUI LAYOUT ==================
app = tk.Tk()
app.title("Intrusion Detection Log Analyzer")
app.geometry("600x500")

selected_file = tk.StringVar()

tk.Label(app, text="Log File Path").pack()
tk.Entry(app, textvariable=selected_file, width=65).pack()
tk.Button(app, text="Browse Log", command=select_log_file).pack(pady=6)

tk.Label(app, text="Failure Threshold").pack()
threshold_input = tk.Entry(app)
threshold_input.pack()
threshold_input.insert(0, "3")

tk.Button(app, text="Analyze Logs", command=start_scan).pack(pady=10)

result_box = tk.Text(app, height=15)
result_box.pack()

app.mainloop()
