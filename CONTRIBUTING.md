# Contributing to SkillGuard

Thank you for your interest in contributing to SkillGuard! 🛡️

## How to Contribute

### Reporting Issues

- Use the [GitHub Issues](https://github.com/gitstq/SkillGuard-CLI/issues) page
- Include the SkillGuard version, target skill format, and sample output
- Describe the expected vs actual behavior

### Adding New Patterns

1. Edit `skillguard/patterns.py`
2. Add a new `VulnPattern` instance to `PATTERNS_DB`
3. Include: pid, name, category, severity, description, regex patterns, confidence, recommendation
4. Run tests to verify

### Code Style

- Follow PEP 8
- Use type hints where appropriate
- Keep zero-dependency constraint (standard library only)
- Add docstrings to all public functions/classes

### Testing

```bash
python -m pytest tests/
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, semicolons, etc.)
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `test:` Adding or updating tests
- `chore:` Build process or auxiliary tool changes

Thank you for making AI agent skills safer! 🚀
