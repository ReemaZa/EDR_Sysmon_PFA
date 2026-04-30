# Log Replay Toggle Guide

## Overview
The EDR agent now supports a simple **toggle** to switch between:
- **Live Sysmon Event Monitoring** (production mode)
- **Log Replay Testing** (development/testing mode)

## How to Use

### 1. Toggle Between Modes
Edit `src/core/agent.py` and find the toggle variable at the top:

```python

READ_FROM_FILE = False
```