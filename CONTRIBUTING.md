# Contributing Guidelines

Thank you for your interest in contributing to the LM Studio Web Browser & JS MCP Server!

## Setup

Before contributing, set up the project locally:

```bash
# Clone the repository
git clone https://github.com/depeler/lm_supermcp.git

# Navigate to the folder and create a virtual environment
cd lm_supermcp
python -m venv venv

# Activate the virtual environment (Windows)
venv\Scripts\activate
# Or on macOS/Linux:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Code Quality

### Python Style

The project adheres to [PEP 8](https://pep8.org/). You can use `black` and `flake8` for formatting and linting:

```bash
# Format code
black mcp_server.py

# Lint code
flake8 mcp_server.py
```

### Running Tests

Ensure all tests pass before submitting changes:

```bash
python test_security.py
python test_mcp.py
```

## Contribution Steps

1. **Fork the repo**: Fork the repository on GitHub.
2. **Create a branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and commit:
   ```bash
   git commit -m "feat: add amazing feature"
   ```
4. **Push your branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**: Submit your PR on GitHub with a clear description.

## Commit Messages

Please follow the [Conventional Commits](https://www.conventionalcommits.org/) convention:

- `fix:` - Bug fixes
- `feat:` - New features
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding or fixing tests
- `chore:` - Miscellaneous tasks

## Security Rules

- Never bypass URL validation safeguards.
- Do not remove JavaScript security restrictions.
- Be cautious when modifying rate limiting thresholds.
- Always include safe error handling on all API requests.

## Questions?

Check the [README.md](./README.md) file or open an issue on GitHub.

Thank you! 🙏