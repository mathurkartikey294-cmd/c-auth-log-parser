# C Auth Log Parser
A command-line based authentication log parser written in **C**.
This project reads an authentication log file, parses SSH login events, identifies successful and failed login attempts, detects suspicious users and suspicious IP addresses, and generates a structured **JSON security report**.

## Features
Parse authentication logs using C
Read log file from command-line arguments
 Extract:
  - Date
  - Time
  - Process/program
  - PID
  - Username
  - IP address
  - Login status
  - Port
Count total login attempts
Count successful logins
Count failed login attempts
Detect suspicious users
Detect suspicious IP addresses
Suspicious activity is detected when:
  - 3 or more failed login attempts occur
  - Attempts occur within a 10-second window
  - Attempts happen on the same date
- Generate a structured JSON security report
- Uses dynamic memory allocation with `malloc()` and `realloc()`
---
## Technologies Used
- C
- Standard C Library
- File Handling
- Structures
- Dynamic Memory Allocation
- String Manipulation
- JSON generation
- Git & GitHub
---
## Project Structure
C-Auth-Log-Parser/
│
├── main.c
├── auth.log
├── final_output.json
├── README.md
└── .gitignore
How It Works
The program follows these steps:
Authentication Log
        │
        ▼
Read Log File
        │
        ▼
Parse Each Log Entry
        │
        ▼
Store Valid Entries
        │
        ├───────────────┐
        ▼               ▼
Successful          Failed
 Logins              Logins
        │               │
        │               ▼
        │       Detect Suspicious
        │       Users / IPs
        │               │
        └───────┬───────┘
                ▼
        Generate JSON Report
Log Format
The parser currently expects SSH authentication logs similar to:
Oct 2 08:01:12 ubuntu-server sshd[1201]: Accepted password for Rahul from 192.168.1.10 port 52344 ssh2
Oct 2 08:03:45 ubuntu-server sshd[1250]: Failed password for aman from 192.168.1.20 port 42321 ssh2
Compilation
Compile the program using GCC:
gcc main.c -o parser
On Windows:
gcc main.c -o parser
Running the Program
Pass the authentication log file as a command-line argument.
Linux
./parser auth.log
Windows
.\parser.exe auth.log
Output
The program generates:
final_output.json
The output contains:
Total login attempts
Successful logins
Failed login attempts
Suspicious users
Suspicious IP addresses

This project was built to practice:
C programming
Structures
Arrays
Pointers
Dynamic memory allocation
File handling
String manipulation
Command-line arguments
Parsing structured text
Security log analysis
JSON data generation
Git and GitHub
Author
Kartikey Kumar Mathur 

Kartikey Mathur

Built as a cybersecurity-focused C programming project.K
