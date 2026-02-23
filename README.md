# 🖥️ System Resource Monitor

A lightweight, web-based system monitoring dashboard built with Python and Flask. It provides real-time visibility into CPU usage, RAM consumption, disk utilization, power status, and the state of user-defined processes — all accessible from a browser, auto-refreshing every 5 seconds.

---

## 📸 Screenshots

./screenshot.png

---

## ✨ Features

- **Real-time system stats** — CPU usage, RAM percentage, and power status (AC / Battery) at a glance
- **Multi-disk monitoring** — Automatically detects and displays usage for all mounted partitions, filtering out virtual filesystems (tmpfs, squashfs, overlay, etc.)
- **Process tracking** — Define a custom list of processes to follow; the dashboard shows each process's PID and live status (`running`, `sleeping`, `zombie`, `Not Running`, etc.)
- **Settings page** — Browse all running processes, add them to the watchlist, or remove them — no config files to edit manually
- **Persistent watchlist** — Followed processes are stored in a plain-text file and survive server restarts
- **Cross-platform** — Supports Windows and Linux
- **Dark-themed UI** — Clean, GitHub-inspired dark interface with responsive design for mobile and desktop

---

## 🛠️ Tech Stack

| Layer     | Technology          |
|-----------|---------------------|
| Backend   | Python 3, Flask     |
| Monitoring| psutil              |
| Frontend  | Jinja2, HTML5, CSS3 |

---

## 📁 Project Structure

```
system-monitor/
│
├── main.py               # Flask application & all monitoring logic
├── prova.txt             # Auto-generated file storing followed process names
│
└── templates/
│   ├── main.html         # Dashboard page
│   └── settings.html     # Process management page
│
└── static/
    └── css/
        └── style.css     # Application stylesheet
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/mdmmt05/system-monitor.git
   cd system-monitor
   ```

2. **Install dependencies**

   ```bash
   pip install flask psutil
   ```

3. **Run the application**

   ```bash
   python main.py
   ```

4. **Open your browser** and navigate to:

   ```
   http://localhost:5000
   ```

---

## ⚙️ Configuration

No configuration file is required. The only persistent state is the list of followed processes, which is automatically stored in `prova.txt` in the same directory as `main.py`.

The application runs in debug mode on `0.0.0.0:5000` by default. For production use, it is recommended to serve it behind a reverse proxy (e.g., Nginx) using a WSGI server such as Gunicorn.

```bash
gunicorn -w 2 -b 0.0.0.0:5000 main:app
```

---

## 📖 Usage

### Dashboard (`/`)

The main page displays:
- Current CPU and RAM usage percentages
- Power status (plugged in or on battery)
- A table of all monitored disks with their usage percentages
- A table of followed processes with their PID and current status

The page **auto-refreshes every 5 seconds**.

### Settings (`/settings`)

From the settings page you can:
- Browse all processes currently running on the system, sorted alphabetically
- **Add** one or more processes to the watchlist by selecting them and clicking *Add Selected to Followed List*
- **Remove** one or more processes from the watchlist by selecting them and clicking *Remove Selected from Followed List*

---

## 🔌 API Routes

| Method | Route              | Description                              |
|--------|--------------------|------------------------------------------|
| GET    | `/`                | Main monitoring dashboard                |
| GET    | `/settings`        | Process management settings page         |
| POST   | `/add_processes`   | Add selected processes to the watchlist  |
| POST   | `/remove_processes`| Remove selected processes from watchlist |

---

## ⚠️ Known Limitations

- **Windows path separator**: The `FOLLOWED_PROCESSES_FILE` path uses a hardcoded backslash (`\\`), which may cause issues on Linux. This is a known issue and should be replaced with `os.path.join()` for full cross-platform compatibility.
- **Process name matching**: Lookup is based on the process name string. If multiple processes share the same name, only the first match is tracked.
- **No authentication**: The dashboard is not protected by any login mechanism. Avoid exposing it on public networks without a reverse proxy with authentication.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss any changes you'd like to make, then submit a pull request.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
