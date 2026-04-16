# Log Ingestion — Inputs, Extractors and Streams

 

**Contributor:** Lekan  Akinsanya

**Role:** Log Ingestion  

**Project:** Catnip Games International SIEM  

 

---

 

## Overview

 

My responsibility was configuring how logs flow into the Graylog

SIEM — setting up the inputs that receive logs, the extractors

that parse raw messages into structured fields, and the streams

that route messages to the right place for analysis.

 

---

 

## Log Sources

 

The Catnip Games environment generates logs from three distinct

sources:

 

| Source | Type | Description |

|---|---|---|

| WSL Ubuntu machine | Real logs | SSH authentication events via rsyslog |

| Python log generator | Simulated logs | Game server, player auth, DDoS, dev SSH |

| Game servers (production) | Real logs (future) | Would replace simulated logs in production |

 

The Python log generator simulates the 300 game servers, player

authentication system, and developer environments described in the

Catnip Games scenario. This is standard practice in security

engineering — synthetic log generation is used to test SIEM

configurations before real infrastructure is connected.

 

---

 

## Inputs

 

Three inputs were configured in Graylog to receive logs from

different sources using different protocols.

 

### Input 1 — Syslog TCP (Port 1514)

 

| Setting | Value |

|---|---|

| Type | Syslog TCP |

| Port | 1514 |

| Bind address | 0.0.0.0 |

| Timezone | Europe/London |

| Encoding | UTF-8 |

 

**Why TCP over UDP for SSH logs:**

TCP guarantees message delivery — if a packet is lost it gets

resent. For security logs, missing a failed login attempt could

mean missing evidence of an attack. TCP was the correct choice.

 

**Why port 1514 not 514:**

Port 514 is the standard Syslog port but requires root privileges

inside the container. Port 1514 is the standard alternative that

avoids this restriction.

 

### Input 2 — Syslog UDP (Port 1514)

 

| Setting | Value |

|---|---|

| Type | Syslog UDP |

| Port | 1514 |

| Bind address | 0.0.0.0 |

| Timezone | Europe/London |

 

UDP is faster and lower overhead than TCP. Some older network

devices and systems can only send Syslog over UDP. This input

provides compatibility for those systems.

 

TCP and UDP on the same port number do not conflict — they are

treated as completely separate addresses by the operating system.

 

### Input 3 — GELF UDP (Port 12201)

 

| Setting | Value |

|---|---|

| Type | GELF UDP |

| Port | 12201 |

| Bind address | 0.0.0.0 |

 

**Why GELF for simulated logs:**

GELF (Graylog Extended Log Format) sends pre-structured JSON

messages. Unlike raw Syslog which arrives as unstructured text,

GELF messages contain named fields that Graylog reads directly

without needing extractors. This is why the game server simulated

logs arrive with structured fields like `event_type`, `server_id`,

`traffic_mbps` automatically.

 

---

 

## Extractors

 

Extractors are applied to the Syslog TCP input only. They parse

raw SSH log messages into structured searchable fields.

 

**Why only Syslog TCP needs extractors:**

GELF messages are already structured — no parsing needed. Syslog

UDP is a fallback input — the primary parsing happens on TCP. Only

Syslog TCP needs extractors because it carries the real SSH logs.

 

### Raw SSH log message (before extractors)

Captain-fresh sshd[32146]: Failed password for invalid user wronguser from 172.27.175.42 port 53424 ssh2

 

### After extractors — structured fields created

 

| Field | Value | Extractor |

|---|---|---|

| event_type | sshd | extract_event_type |

| action | failed | extract_action |

| username | wronguser | extract_username |

| source_ip | 172.27.175.42 | extract_source_ip |

 

### Extractor 1 — extract_event_type

 

| Setting | Value |

|---|---|

| Type | Regular expression |

| Regex | `(sshd)` |

| Condition | Field contains string: `sshd` |

| Store as | `event_type` |

 

### Extractor 2 — extract_action

 

| Setting | Value |

|---|---|

| Type | Regular expression |

| Regex | `(?i)(failed\|accepted\|invalid)` |

| Condition | Field contains string: `sshd` |

| Store as | `action` |

| Converter | Lowercase string |

 

The `(?i)` flag makes matching case-insensitive. The Lowercase

converter normalises all values to lowercase ensuring consistent

querying — `failed` not `Failed`.

 

### Extractor 3 — extract_username

 

| Setting | Value |

|---|---|

| Type | Regular expression |

| Regex | `for (?:invalid user \|user )?(\w+) from` |

| Condition | Field contains string: `sshd` |

| Store as | `username` |

 

The `(?:invalid user |user )?` is a non-capturing group that

handles both "Failed password for root" and "Failed password for

invalid user wronguser" formats.

 

### Extractor 4 — extract_source_ip

 

| Setting | Value |

|---|---|

| Type | Regular expression |

| Regex | `from (\d+\.\d+\.\d+\.\d+)` |

| Condition | Field contains string: `sshd` |

| Store as | `source_ip` |

 

---

 

## rsyslog Configuration

 

rsyslog forwards real SSH authentication logs from the WSL machine

to Graylog in real time.

 

**Configuration file:** `/etc/rsyslog.d/60-graylog.conf`

 

```conf

# Forward auth logs (SSH) to Graylog via TCP syslog

auth,authpriv.* action(

 type="omfwd"

 target="127.0.0.1"

 port="1514"

 protocol="tcp"

)

```

 

**How it works:**

Every time an SSH event occurs on the WSL machine, Linux writes

it to `/var/log/auth.log`. rsyslog watches that file continuously

and immediately forwards any new entry to `127.0.0.1:1514`. Docker

port mapping forwards that to the Graylog container.

 

**Why 127.0.0.1 reaches the container:**

When Docker maps port `1514:1514/tcp`, it creates a rule on the

host machine that forwards anything arriving at port 1514 into

the Graylog container. rsyslog sending to `127.0.0.1:1514` on the

host machine automatically reaches Graylog inside Docker.

 

---

 

## Streams

 

Streams route incoming messages to logical buckets for separate

analysis and alerting.

 

### Stream 1 — ssh-auth

 

| Setting | Value |

|---|---|

| Rule | event_type must match exactly: `sshd` |

| Purpose | Real SSH authentication logs |

| Remove from Default Stream | Yes |

 

### Stream 2 — game_server

 

| Setting | Value |

|---|---|

| Rule 1 | event_type must match exactly: `player_auth` |

| Rule 2 | event_type must match exactly: `game_traffic` |

| Rule 3 | event_type must match exactly: `dev_ssh` |

| Match condition | At least one rule must match |

| Purpose | All simulated game infrastructure logs |

| Remove from Default Stream | Yes |

 

**Why "at least one" not "all":**

A message cannot be `player_auth` AND `game_traffic` AND `dev_ssh`

simultaneously. Using "all rules must match" would mean no message

ever routes to this stream. "At least one" correctly catches any

of the three event types.

 

---

 

## Key Learning

 

The most significant challenge was understanding the difference

between structured and unstructured log ingestion. Raw Syslog

messages are plain text — every piece of information is buried

inside a string and needs extractors to become searchable. GELF

messages arrive pre-structured with named fields. Choosing the

right input type and understanding when extractors are needed vs

not needed was the central technical skill developed in this role. 
