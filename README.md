![Repository banner for @whallin/openpgp-bulk-cert-gen](https://raw.githubusercontent.com/whallin/.github/refs/heads/main/banner.png)

# @whallin/openpgp-bulk-cert-gen

PowerShell 5.1+ script for bulk generation of OpenPGP certificates.

## Requirements

- PowerShell 5.1 or later
- Gpg4win (gpg) installed and in PATH
  - Download: https://www.gpg4win.org/get-gpg4win.html

## Getting Started

1. Create or edit `certificates.json`:

```json
[
  {
    "name": "John Doe",
    "primaryEmail": "john.doe@example.com",
    "passphrase": "SecurePass123!",
    "additionalEmails": ["j.doe@example.com"]
  }
]
```

2. Run the script:

```powershell
.\Generate-PGPCertificates.ps1
```

## Configuration

Available script parameters:

- `ConfigFile` - Path to JSON config (default: `certificates.json`)
- `DefaultKeyType` - Primary key algorithm (default: `EDDSA`)
- `DefaultKeyCurve` - Primary key curve (default: `Ed25519`)
- `DefaultSubkeyType` - Subkey algorithm (default: `ECDH`)
- `DefaultSubkeyCurve` - Subkey curve (default: `Cv25519`)
- `DefaultExpirationYears` - Years until expiration (default: `5`)

### Per-certificate Configuration

All fields in JSON are optional except `name`, `primaryEmail`, and `passphrase`:

```json
{
  "name": "Jane Smith",
  "primaryEmail": "jane@example.com",
  "passphrase": "SecurePass456!",
  "additionalEmails": ["j.smith@example.com"],
  "keyType": "EDDSA",
  "keyCurve": "Ed25519",
  "subkeyType": "ECDH",
  "subkeyCurve": "Cv25519",
  "expirationYears": 10
}
```

## Output

For each certificate, three files are generated:

- `{email}.public.asc` - Public key (safe to share)
- `{email}.private.asc` - Private key (keep secure!)
- `{email}.revocation.asc` - Revocation certificate (keep secure!)

All files are saved to `pgp_certificates/` directory.

## Examples

### Default Settings

```powershell
.\Generate-PGPCertificates.ps1
```

Uses Ed25519/Cv25519 keys with a 5-year expiration.

### Custom Expiration

```powershell
.\Generate-PGPCertificates.ps1 -DefaultExpirationYears 10
```

Uses Ed25519/Cv25519 keys with a 10-year expiration.

### Mixed Configuration

Use `certificates.example.json` to see how to mix default and per-certificate settings.

## Troubleshooting

### Error: "GnuPG not found"

- Install GnuPG and ensure it's in your system PATH
- Restart PowerShell after installation

### Error: "Cannot parse JSON"

- Validate JSON syntax at https://jsonlint.com
- Ensure UTF-8 encoding
- Check for trailing commas
