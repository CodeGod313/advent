# ADVENT

Toolset that allows you extract events from SIEM (MaxPatrol 10) and compose process trees.

## EXTRACTOR

Extracts events from MaxPatrol and writes them to file events.json

```bash
usage: extractor.py [-h] --url URL --token TOKEN --time-from 'DD.MM.YYYY HH:MM:SS' --time-to 'DD.MM.YYYY HH:MM:SS' [--filter FILTER]
                    [--select SELECT] [--limit LIMIT] [--tz TZ] [--timeout TIMEOUT] [-k] [-v]
```

Example usage:

```bash
python extractor.py --url https://siem-en.city12.stf/ --token 'pat_C0020B8C5EDD41CAC4A0F7B1D7AF70F04D43BFB7A98C3AB265BA0C39F8CB9A21' --time-from '22.11.2023 07:00:00' --time-to '22.11.2023 09:00:00' -k --filter 'object = "process" and event_src.host = "tsantos.uf.city.stf"' --tz UTC
```

## PROCESS TREE BUILDER

Builds process tree

```bash
usage: build_process_tree.py [-h] [--full] [--max-cmd N] [--decode] [--color {auto,always,never}] [--no-color] [--pid PID |
                             --tree-of PID]
                             [file]

Build a text process tree from a Windows event-log JSON export.

positional arguments:
  file                  JSON export (omit or '-' to read from stdin)

options:
  -h, --help            show this help message and exit
  --full, -f            show full command lines (no '...' truncation)
  --max-cmd N           truncate header command lines longer than N chars (default: 200; ignored with --full)
  --decode, -d          base64-decode PowerShell -EncodedCommand payloads; encoded blob becomes '<decoded: N line(s)>' in the header
                        and the script is printed below
  --color {auto,always,never}
                        ANSI color output (default: auto — on when stdout is a TTY)
  --no-color            disable color (same as --color never)
  --pid PID             show only the subtree rooted at PID
  --tree-of PID         show the entire tree containing PID
```

Example usage:

```bash
python build_process_tree.py --full --decode --tree-of 624 events.json
```

## RESULT

<img width="1897" height="941" alt="image" src="https://github.com/user-attachments/assets/e18ec2df-e3ba-417a-8815-2982f08e72ea" />

