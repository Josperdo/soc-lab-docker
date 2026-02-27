# Contributing to SOC Lab Docker

Thank you for your interest in contributing to **SOC Lab Docker**! This project is built for the community, by the community. Whether you're adding detection rules, attack simulations, documentation, or bug fixes, contributions are welcome.

---

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
   ```bash
   git clone https://github.com/yourusername/soc-lab-docker.git
   cd soc-lab-docker
   ```
3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-detection-rule
   ```
4. **Make your changes**
5. **Test thoroughly** (see below)
6. **Commit with clear messages**
   ```bash
   git commit -m "Add brute-force detection query for Windows authentication"
   ```
7. **Push to your fork** and **open a pull request**

---

## Types of Contributions

### 1. Detection Queries

Add new detection rules to `detections/`:

- Format: SPL, KQL, PromQL, or other supported languages
- Include documentation: purpose, logic, tuning guidance, MITRE ATT&CK mapping
- Test against mock lab data
- Avoid false positives

**Example workflow:**

```bash
git checkout -b feature/add-psexec-detection

# Create new detection files
cat > detections/lateral_movement/psexec_detection.spl << 'EOF'
# Detect PsExec execution
...
EOF

# Document it
cat > detections/lateral_movement/psexec_notes.md << 'EOF'
## PsExec Detection
Purpose: Identify lateral movement via PsExec
...
EOF

# Test
# 1. Import into lab UI
# 2. Run `./scripts/lateral_movement_simulation.sh`
# 3. Verify detection fires

git add detections/lateral_movement/
git commit -m "Add PsExec lateral movement detection (T1570)"
git push origin feature/add-psexec-detection
```

### 2. Attack Simulation Scripts

Enhance attack scenarios in `scripts/`:

- Format: Bash or Python
- Document parameters and expected outputs
- Test with lab stack running
- Include safety warnings

**Example:**

```bash
git checkout -b feature/add-ransomware-simulation

# Create new script
cat > scripts/ransomware_simulation.sh << 'EOF'
#!/bin/bash
# Simulate ransomware file encryption patterns
...
EOF

chmod +x scripts/ransomware_simulation.sh

# Document it
cat >> scripts/README.md << 'EOF'
### Ransomware Simulation
./ransomware_simulation.sh --target-dir /data --file-count 1000
EOF

# Test
./scripts/ransomware_simulation.sh --help
./scripts/ransomware_simulation.sh --target-dir /tmp/test

git add scripts/
git commit -m "Add ransomware encryption simulation (T1486)"
git push origin feature/add-ransomware-simulation
```

### 3. Dashboards & Visualizations

Add examples to `dashboards/`:

- Format: JSON export from Kibana/Grafana
- Include description and instructions
- Document visualizations and queries
- Test importing into clean environment

### 4. Documentation

Improve guides and learning resources:

- Clarify setup instructions
- Add troubleshooting sections
- Create learning path tutorials
- Add diagrams or walkthroughs

### 5. Bug Fixes

Report and fix issues:

- Search [GitHub Issues](https://github.com/yourusername/soc-lab-docker/issues) first
- Include reproduction steps
- Test the fix thoroughly

---

## Testing Your Changes

### For Detection Queries

```bash
# 1. Start lab
docker-compose up -d

# 2. Load your query in UI (Kibana)
# http://localhost:5601

# 3. Validate it runs without errors
# Edit, test, iterate

# 4. Trigger the attack
./scripts/brute_force_simulation.sh --target-user admin --attempts 50

# 5. Verify detection fires
# (Should see alert or result in dashboard)

# 6. Test negative case (no attack = no alert)
docker-compose down
docker-compose up -d
# Wait 2 minutes
# Run your query
# Should return 0 or very low count (no false positive)
```

### For Attack Scripts

```bash
# 1. Review your script for syntax errors
shellcheck scripts/your_new_script.sh

# 2. Dry-run (if supported)
./scripts/your_new_script.sh --dry-run

# 3. Test with detection queries running
docker-compose up -d

# Watch detection logs
docker-compose logs -f

# Run your attack in another terminal
./scripts/your_new_script.sh

# Verify events appear and are detected
curl "http://localhost:9200/logs-*/_count"
```

### For Documentation

- Build the docs locally (if applicable)
- Test code examples yourself
- Check links are valid
- Verify formatting renders correctly

---

## Code Style & Standards

### Detection Queries

- Use descriptive names and comments
- Include baseline methodology
- Document field assumptions
- Test on realistic data volumes

### Bash Scripts

- Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- Include error handling
- Add helpful comments
- Test on bash 4.0+

### Python Scripts

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints
- Include docstrings
- Test on Python 3.8+

### Documentation

- Use clear, concise language
- Include examples
- Add references and links
- Keep sections short and scannable

---

## Commit Message Guidelines

Write clear, descriptive commit messages:

```
Add feature/fix/docs: Brief summary (50 chars max)

Longer explanation if needed, wrapped at 72 characters.
Explain the "why" not the "what".

Reference issue if applicable: Fixes #123

- Bullet points for additional details
- Keep format consistent
```

**Examples:**

```
Add brute-force detection for Windows authentication
Fix Elasticsearch connection timeout in log aggregator
Update architecture documentation with data flow diagram
```

---

## Pull Request Process

1. **Update the README.md** if adding new features
2. **Add tests** if applicable
3. **Document your changes** clearly in PR description
4. **Link related issues** with `Fixes #123`
5. **Be responsive** to code review feedback

### PR Template

```markdown
## Description

Brief overview of your changes

## Type of Change

- [ ] New feature (detection, dashboard, script)
- [ ] Bug fix (broken query, wrong documentation)
- [ ] Documentation (clarification, new guide)
- [ ] Refactor (no functional change)

## Related Issue

Fixes #(issue number)

## Testing

- [ ] Tested locally in Docker environment
- [ ] All detection queries validated
- [ ] No breaking changes to existing queries
- [ ] Documentation updated

## Checklist

- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented complex areas
- [ ] I have tested thoroughly
- [ ] Documentation is clear and complete
```

---

## Questions or Need Help?

- Open an **issue** on GitHub
- Check **existing discussions**
- Review **architecture documentation** (docs/ARCHITECTURE.md)
- Reach out via email (if applicable)

---

## Recognition

Contributors are recognized in:

- [README.md](README.md) – Hall of fame
- GitHub contributors page
- Release notes for each version

Thank you for making SOC Lab Docker better.

---

**Last Updated:** February 2026
