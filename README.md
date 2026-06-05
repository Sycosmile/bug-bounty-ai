# Bug Bounty AI

Modular bug bounty intelligence system with AI-powered security analysis.

## Features

- **Recon Automation** - Subdomain discovery and enumeration
- **Exposure Detection** - Service identification with Nmap
- **Web Scanning** - Vulnerability detection with Nikto
- **API Analysis** - API endpoint discovery and testing
- **Smart Inspector** - Pattern recognition and risk flagging
- **Dynamic Skill Loading** - Extensible skill registration system
- **AI Planning Engine** - Intelligent skill sequencing

## Architecture

### Core Components

- **Engine** - Orchestrates skill execution with AI planning
- **Registry** - Dynamically registers available skills
- **Context** - Maintains target state throughout analysis
- **Loader** - Auto-discovers and loads skill modules

### Skills

The system includes 7 modular skills:

| Skill | Purpose | Dependencies |
|-------|---------|--------------|
| recon | Subdomain discovery | subfinder tool |
| exposure | Service enumeration | nmap tool |
| web_scan | Web vulnerability scanning | nikto tool |
| api_scan | API endpoint discovery | requests library |
| api_tester | API behavior analysis | requests library |
| inspector | Pattern analysis & insights | core modules |
| report | Summary generation | core modules |

## Usage

```bash
python main.py
```

Enter target domain when prompted.

## Setup

1. Install dependencies:
   ```bash
   pip install requests
   ```

2. Install optional tools:
   - **subfinder** - for subdomain enumeration
   - **nmap** - for service scanning
   - **nikto** - for web vulnerability scanning

3. Run the system:
   ```bash
   python main.py
   ```

## Project Structure

```
bug-bounty-ai/
├── main.py              # Entry point
├── core/
│   ├── context.py       # State management
│   ├── registry.py      # Skill registration
│   ├── engine.py        # Execution engine
│   └── loader.py        # Dynamic skill loading
├── skills/
│   ├── recon.py
│   ├── exposure.py
│   ├── web_scan.py
│   ├── api_scan.py
│   ├── api_tester.py
│   ├── inspector.py
│   └── report.py
├── tools/
│   ├── subfinder.py     # Subdomain enumeration
│   ├── nmap.py          # Service scanning
│   └── nikto.py         # Web scanning
└── ai/
    └── planner.py       # AI skill planning
```

## How It Works

1. **Initialization**: Load target from user input
2. **Skill Discovery**: Dynamic loader discovers all skills in `skills/` directory
3. **Execution Loop**: AI planner chooses next optimal skill
4. **Context Updates**: Each skill processes and updates context
5. **Completion**: Stop when analysis is complete
6. **Report**: Generate and display findings summary

## Error Handling

- Skills include error handling for missing external tools
- System continues execution with graceful fallbacks
- Warnings logged for tool failures

## Development

To add a new skill:

1. Create `skills/new_skill.py`:
   ```python
   def run(context):
       # Process context
       return context
   
   skill = {"name": "new_skill", "run": run}
   ```

2. Loader will automatically discover and register it

## License

MIT
