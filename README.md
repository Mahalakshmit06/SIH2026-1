# NCB - DIGITAL CHAIN OF CUSTODY

**SECURE TEST & AUDIT DASHBOARD**

**NCB — Secure Test & Audit | Enterprise Audit Node**

A tamper-evident evidence and audit system. Each received field result —
evidence photograph, classification, source, GPS and timestamp — is recorded,
fingerprinted with SHA-256, verified on demand, and tracked through a
persistent audit log. Positive findings can be legally certified and sealed
under Section 52A of the Bharatiya Sakshya Adhiniyam for use in trial.

## What the dashboard provides

**Supervisor Operations**

- **Dashboard** — live totals and the most recent test records.
- **Test Records** — search by Test ID / Officer / Source, filter by
  classification / district / area, and open any record by selecting its row.
- **Area Analysis** — retrieve historical records for an operational area,
  with classification counts, GPS map and per-record map links.
- **Register Record** — log a newly received test result with its captured
  evidence and case details; a `NCB-YYYYMMDD-###` Test ID is assigned and the
  SHA-256 fingerprint is generated on the spot.
- **Audit Log** — a persistent, chronological record of every action.

**Magistrate Portal** (switch the Role at the top of the sidebar)

- **Pending Section 52A Certifications** — only positive findings awaiting
  certification; each row opens a review screen with the record metadata and
  the original evidence photograph.
- **Sealed Dockets** — records certified and locked for trial, with the
  certifying magistrate, certification timestamp and locked SHA-256 hash.
- **Audit Log** — the same persistent audit trail.

## Certification and verification

Every record carries a cryptographic fingerprint of its fields **plus** the
captured evidence image. SHA-256 verification is always explicit — a record is
shown as `NOT VERIFIED` until you select **VERIFY RECORD**:

```
RECORD VERIFIED            when the current fingerprint == stored fingerprint
TAMPER DETECTED            when they differ (modification detected)
VERIFICATION REQUIRED      when the evidence is unavailable to verify
```

Certification under **Section 52A** follows a strict flow:

```
PENDING
  → VERIFY RECORD            (explicit SHA-256 comparison required)
  → SHA-256 MATCH
  → RECORD VERIFIED
  → Aadhaar / VID + OTP      (credential-validation interface only)
  → APPLY DIGITAL SIGNATURE & CERTIFY EVIDENCE
  → LEGALLY SEALED (SEC 52A)
```

Certification controls stay **disabled until the record is successfully
verified**. At certification time the exact verified SHA-256 hash is stored
separately as the **CERTIFIED / LOCKED SHA-256 HASH** and any later verification
is compared against that locked reference. If the record or its evidence is
altered at any point, verification reports `TAMPER DETECTED` /
`TAMPERING DETECTED` / `INTEGRITY MISMATCH` and certification is blocked.

In this SIH implementation the Aadhaar / VID and OTP fields are a
credential-validation interface only — no live Aadhaar authentication or
legally binding digital signature is performed. The OTP and Aadhaar number are
never stored or logged; the `MAGISTRATE_CERTIFIED` audit entry records the Test
ID, Magistrate ID, the exact certification timestamp and the locked SHA-256
hash reference.

**Sealed records are permanently read-only.** Once `LEGALLY SEALED (SEC 52A)`,
the classification, operational area, notes, evidence image, original timestamp
and stored SHA-256 hash can no longer be modified — the Record Modification
function is disabled for them. Sealed dockets may only be viewed and verified,
and their **SHA-256 HASH (LOCKED)** is shown in Sealed Dockets.

## Project structure

```
NCB_Digital_Chain_of_Custody/
├── app.py                 # NCB - DIGITAL CHAIN OF CUSTODY interface
├── services/
│   ├── database.py        # secure record storage layer + Section 52A state
│   ├── integrity.py       # SHA-256 fingerprint generation & verification
│   ├── audit.py           # persistent audit log
│   └── bootstrap.py       # initial records with captured field evidence
├── data/                  # store (auto-created on first run)
├── requirements.txt
└── README.md
```

## Run

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

On first launch the node provisions a set of test records, each with its own
captured field-evidence photograph, ready to explore.

## Guided walkthrough

1. **Dashboard** — live summary cards and the latest records.
2. **Test Records → select `NCB-20260919-006`** — evidence photograph on the
   left, record information on the right (classification, source, capture time,
   GPS, location link, officer, certification status and tamper status).
3. **VERIFY RECORD** — shows `RECORD VERIFIED` until the record is modified.
4. **Record Review** — change the classification and save (the original
   fingerprint is preserved for tamper detection).
5. **VERIFY RECORD again** — shows `TAMPER DETECTED`, proving tamper detection.
6. **Audit Log** — the modification event is shown immediately.
7. **Switch Role → Magistrate Portal → Pending Section 52A Certifications** —
   review the metadata and evidence of a positive finding.
8. **VERIFY RECORD**, then enter an Aadhaar / VID and OTP and select
   **APPLY DIGITAL SIGNATURE & CERTIFY EVIDENCE** — the record becomes
   `LEGALLY SEALED (SEC 52A)` and is logged as `MAGISTRATE_CERTIFIED`.
9. **Sealed Dockets** — the certified record now appears with its locked
   SHA-256 hash and certifying magistrate.
10. **Area Analysis** — retrieve records by operational area and view them
    on the map with GPS links.

## Evidence images

Each seeded record has its own realistic field-evidence photograph (a
lateral-flow cassette on a color-reference card). The sample line color varies
between records so every screenshot is visually distinct. Deployments can
replace these with the team's actual field photographs.