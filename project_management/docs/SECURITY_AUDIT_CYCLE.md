# Dependency & Security Audit Cycle

Run this weekly in maintenance:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\security_audit_cycle.ps1
```

What it runs:

- `pip check`
- `pip list --outdated`
- `pip-audit` (if installed)

Output logs:

- `logs/security_audit_YYYYMMDD_HHMMSS.log`

Recommended workflow:

1. Review vulnerable/outdated packages.
2. Upgrade patch/minor versions in a branch.
3. Run full tests.
4. Deploy with rollback plan.

