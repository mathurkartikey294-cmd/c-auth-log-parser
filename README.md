# C Auth Log Parser
A command-line based authentication log parser written in **C**.
This project reads an authentication log file, parses SSH login events, identifies successful and failed login attempts, detects suspicious users and suspicious IP addresses, and generates a structured **JSON security report**.
---
## Features
- Parse authentication logs using C
- Read log file from command-line arguments
- Extract:
  - Date
  - Time
  - Process/program
  - PID
  - Username
  - IP address
  - Login status
  - Port
- Count total login attempts
- Count successful logins
- Count failed login attempts
- Detect suspicious users
- Detect suspicious IP addresses
- Suspicious activity is detected when:
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
Example:
{
    "login_attempts": 10,
    "successful_logins": 6,
    "failed_attempts": 4,
    "suspicious_users": [
        {
            "username": "rahul",
            "failed_attempts": 3,
            "ip": "192.168.1.10",
            "event": "sshd",
            "port": 52344,
            "pid": 1201
        }
    ],
    "suspicious_ips": [
        {
            "ip": "192.168.1.10",
            "failed_attempts": 3,
            "username": "rahul",
            "event": "sshd",
            "port": 52344,
            "pid": 1201
        }
    ]
}
Suspicious User Detection
A user is considered suspicious when:
3 or more failed login attempts
        +
within 10 seconds
        +
same username
        +
same date
For example:
08:01:01 Failed password for rahul
08:01:05 Failed password for rahul
08:01:09 Failed password for rahul
This will be reported as suspicious activity.
Suspicious IP Detection
Similarly, an IP address is considered suspicious when:
3 or more failed login attempts
        +
within 10 seconds
        +
same IP address
        +
same date
Memory Management
The project uses dynamic memory allocation.
Initially:
int capacity = 2;
Memory is allocated using:
malloc()
When the allocated space becomes full, the array is expanded using:
realloc()
A temporary pointer is used while reallocating to avoid losing the original memory block if realloc() fails.
Finally, allocated memory is released using:
free(users);
Command-Line Arguments
The program requires exactly one argument:
./parser <log_file>
Example:
./parser auth.log
If no log file is provided, the program displays an error message.
Error Handling
The program handles:
Missing command-line arguments
Failure to open the log file
Failure of dynamic memory allocation
Failure to create the JSON output file
Current Limitations
The parser currently expects a specific SSH log format.
Only the currently supported log format is parsed.
JSON is generated manually using fprintf().
Suspicious activity detection currently uses a 10-second time window.
The parser currently works with the date and time format present in the input logs.
Future Improvements
Possible future improvements:

Support multiple authentication log formats
Accept output filename through command-line arguments
Add command-line options
Improve malformed-line reporting
Add more security detection rules
Detect brute-force attacks
Detect suspicious login locations
Generate CSV reports
Add configuration through a .env file
Add unit tests
Improve JSON generation
Add support for larger log files
Learning Objectives

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

Kartikey Mathur

Built as a cybersecurity-focused C programming project.