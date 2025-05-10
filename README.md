# win_ps

`win_ps` is a console utility that brings a Linux-style `ps` command experience to Windows. 
It allows you to list, filter, sort, and format processes — all without requiring administrator privileges.

---

## ✅ Features

- Fully supports GNU-style options like `ps -ef`, `ps -fl`, `ps -l`
- Custom output columns via `-o` option
- Multi-key and reverse sorting via `--sort`
- No administrator rights required
- Supports fields: `cmd`, `name`, `stime`, `c`, `pri`, `ppid`, `user`, etc.

---

## 🛠 Usage

```sh
ps [options]
```

### 🔹 Default Output

```sh
win_ps
```
Displays: `PID TIME CMD NAME`

### 🔹 Full Format (Command Line)
```sh
ps -f
```

### 🔹 Long Format
```sh
ps -l
```

### 🔹 Filter by User
```sh
ps -u USER
```

### 🔹 Filter by Executable Name
```sh
ps -C java.exe
```

### 🔹 Filter by PID
```sh
ps -p 1234
```

### 🔹 Sort by Field
```sh
ps --sort pid
```

### 🔹 Select Output Fields
```sh
ps -o pid,ppid,time,c,cmd

### 🔹 Version Info
```sh
ps -v
```

---

## 🧾 Output Field Descriptions

| Field   | Description                          |
|---------|--------------------------------------|
| `pid`   | Process ID                           |
| `ppid`  | Parent Process ID                    |
| `user`  | Username running the process         |
| `cmd`   | Full command line                    |
| `name`  | Executable name                      |
| `time`  | Cumulative CPU time (MM:SS)          |
| `c`     | CPU usage percentage (0–100%)        |
| `pri`   | Process priority                     |
| `stime` | Start time (HH:MM)                   |

---

## 📝 License

MIT License

---

## 🙏 Contributors

- Developer: @ice3x2
- Co-designer/Support: ChatGPT (OpenAI)

---

If this tool helps you, consider giving it a ⭐ star!
