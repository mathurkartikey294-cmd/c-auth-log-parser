# C Auth Log Parser

A small command-line tool written in C that parses Linux SSH authentication logs (`auth.log` style) and prints a summary of login activity. It also flags usernames and IP addresses with repeated failed logins, which can be a sign of a brute-force attack.

## Features

- Takes the log file path as a command-line argument
- Extracts these fields from each SSH login line: month, date, time, program, PID, status, username, source IP and port
- Prints a summary: total login attempts, successful logins and failed logins
- Flags suspicious usernames and source IPs with 3 or more failed attempts
- Skips malformed or unsupported lines without crashing
- Uses dynamic memory (`malloc` / `realloc`), so the log file can have any number of lines

## Build

You need a C compiler such as `gcc`.

```
gcc main.c -o logparser
```

## Usage

```
logparser <logfile>
```

Examples (PowerShell):

```
.\logparser auth.log
.\logparser "C:\Users\Admin\Downloads\auth.log"
```

Put the path in quotes if it contains spaces. If no file is given, the tool prints a usage message and exits.

## Supported log format

The parser reads SSH password login lines like these:

```
Oct  2 08:01:12 ubuntu-server sshd[1201]: Accepted password for rahul from 192.168.1.10 port 52344 ssh2
Oct  2 08:15:30 ubuntu-server sshd[1302]: Failed password for root from 203.0.113.45 port 40122 ssh2
Oct  2 08:22:05 ubuntu-server sshd[1340]: Failed password for invalid user admin from 198.51.100.23 port 33890 ssh2
```

Fields extracted from each line:

| Field | Example |
|---|---|
| Timestamp | `Oct  2 08:01:12` |
| Program and PID | `sshd[1201]` |
| Status | `Accepted` / `Failed` |
| Username | `rahul` |
| Source IP | `192.168.1.10` |
| Port | `52344` |

## Example output

```
Total login attempts are 15
Successful login are 3
Failed attempts are 12
Suspicious user name = root (failed attempts = 6)
Suspicious user name = admin (failed attempts = 3)
Suspicious ip address  = 203.0.113.45 (failed attempts = 6)
Suspicious ip address  = 198.51.100.23 (failed attempts = 3)
```

## How it works

1. `main` checks that exactly one argument (the file path) was given
2. The file is read line by line with `fgets`
3. Each line is parsed with `sscanf`; a line is accepted only if all 9 fields are read, otherwise it is skipped
4. Accepted entries are stored in a dynamic array of structs that grows with `realloc`
5. `report()`, `detectsun()` and `detectsip()` run over the stored entries
6. The memory is freed before the program exits

## Known limitations

- Only `password` logins are parsed. `Accepted publickey` lines are skipped
- The hostname `ubuntu-server` is hardcoded in the parse format
- `sudo`, session open/close and `[preauth]` lines are skipped
- The suspicious threshold (3 failed attempts) is fixed in the code

## Planned improvements

- Support `publickey` logins
- Top targeted usernames and top source IPs as a ranked list
- Time gap between logins
- Configurable threshold from the command line

## Concepts used

Structs, pointers, strings, file handling, dynamic memory allocation, command-line arguments (`argc` / `argv`).