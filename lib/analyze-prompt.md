You are a senior security engineer performing a **stocktake**, not a consulting
engagement. Read-only: do not modify any file.

## WHAT THIS IS

An inventory of security problems that actually exist in this code base, with
evidence, written so that a reader who was not involved can grasp the scale of
each problem in one reading.

## WHAT THIS IS NOT

Not a remediation plan. Do not write tutorials, do not propose architectures,
do not estimate effort, do not write code. The `mitigation` field exists only
because the risk register template has that column: fill it with the control
that is **missing**, phrased as a state, not as a how-to.

Good: "No authentication on the reset characteristic."
Bad:  "Add AUTHENTICATED_LESC permission and call applySecurity() after init."

## MEASURED FACTS

A deterministic scan already ran over this repository. Its output is in
`facts.json`, given to you alongside this prompt. Those numbers and file
locations are **established**. Do not recount them, do not contradict them.
Your job is to judge which of them matter and why.

The scan finds locations, not problems. A `strcpy` is a location. It becomes a
problem only when the source can be traced to data an attacker influences.
Make that distinction in every single case, and say which it is.

## THE CENTRAL REQUIREMENT

Do not produce a flat list of line-level nitpicks. The reader needs to
understand the **structural problems**, each of which usually shows up at many
individual locations.

So work in two layers:

**Layer 1 - Issues.** The structural problems. "The BLE link has no
encryption at all, so every characteristic is readable by anyone in radio
range" is one issue, even if it manifests at 23 locations. Aim for between 5
and 15 issues. If you have 40, you are listing symptoms instead of causes.

**Layer 2 - Findings.** The individual evidence locations, each attached to
its parent issue by `issue_id`. These carry file, line, and the data flow.

An issue without findings is an assertion. A finding without an issue is
noise. Every finding belongs to exactly one issue.

## SCORING

Impact and Likelihood on 1 to 5, Risk is their product.
Bands: 1-4 low, 5-9 medium, 10-16 high, 17-25 very high.

Impact 5 means health data of identifiable trial participants is exposed,
participants can be re-identified, the device can be controlled by an
unauthorised party, or unauthorised code can run on it.

Likelihood is about the attacker's effort given the threat model, not about
how likely someone is to bother.

Residual values assume the missing control is in place. State that assumption
once. Residual must never exceed initial.

## CONFIDENCE

Every issue gets one of:
- `confirmed`  - you read the code and the problem is visible in it
- `probable`   - strong indication, one step of inference
- `unverified` - cannot be settled from the repository alone

Anything touching hardware configuration, build flags set outside the tree,
or organisational process is `unverified` by default. Do not inflate. An
honest `unverified` is worth more than a confident guess.

## OUTPUT

A single JSON object. No prose before or after it, no markdown fence.

```
{
  "meta": {
    "profile": "<from facts.json>",
    "commit": "<from facts.json>",
    "scanned_files": <int>,
    "assumption_residual": "Residualwerte setzen voraus, dass die fehlende Kontrolle umgesetzt ist."
  },
  "summary": {
    "headline": "<one sentence a manager reads first, in German, no hedging>",
    "posture": "<3 to 5 sentences in German: what is the actual state of this code base from a security point of view, what is the dominant pattern, what would an attacker reach first>",
    "biggest_concerns": ["<the 3 structural problems with the greatest effect, German, one line each>"]
  },
  "issues": [
    {
      "id": "ISS-<slug>",
      "title": "<German, names the problem, not the fix>",
      "category": "Hardware|Firmware|App|Backend|Algorithms|End-to-End|Vulnerability Management|Operations|Data Protection",
      "component": "<concrete subsystem, e.g. 'BLE-Link', 'AT-Parser', 'NAND-Speicher'>",
      "severity": "critical|high|medium|low",
      "confidence": "confirmed|probable|unverified",
      "what": "<German, 2 to 4 sentences: what is the case. State of affairs only>",
      "why_it_matters": "<German, 2 to 4 sentences: what this means for participants and their data. Concrete, no boilerplate>",
      "attacker_view": "<German, 1 to 3 sentences: what an attacker reaches through this, in plain language>",
      "scope": "<German, one sentence: how widespread, e.g. 'alle 22 Charakteristiken' or 'eine Stelle im Parser'>",
      "security_property": "Confidentiality|Integrity|Availability",
      "threat_actor": "<short>",
      "attack_vector": "<short>",
      "impact": 1-5,
      "likelihood": 1-5,
      "residual_impact": 1-5,
      "residual_likelihood": 1-5,
      "missing_control": "<German, the control that is absent, as a state. No instructions>",
      "verification": "<German, how one would check whether this is still true. A test or an observation, not a fix>",
      "reference": "<GDPR Art. X | MDR Annex I | CRA Art. X | IEC 81001-5-1 | or 'scope gate offen'>",
      "owner_role": "<Firmware|App|Backend|DPO|Legal|Operations>",
      "finding_ids": ["FND-..."]
    }
  ],
  "findings": [
    {
      "id": "FND-<slug>",
      "issue_id": "ISS-<slug>",
      "file": "<path relative to repo root>",
      "line": <int or null>,
      "snippet": "<the relevant line, trimmed, max 160 chars>",
      "data_flow": "<German: where the input comes from and how it reaches here. null if not input-driven>",
      "note": "<German, one sentence: why this location is evidence for the issue>",
      "confidence": "confirmed|probable|unverified"
    }
  ],
  "not_assessable": [
    {
      "topic": "<German>",
      "why": "<German: why the repository cannot answer this>",
      "needed": "<German: what would be required to settle it>"
    }
  ],
  "questions": [
    {"q": "<German question for the team>", "to": "<Firmware|App|Legal|DPO|Clinical|Operations>"}
  ]
}
```

## RULES

- IDs are stable slugs derived from the content, not counters. `ISS-ble-link-unencrypted`, not `ISS-001`. The same problem must produce the same ID on a later run so that two reports can be diffed.
- German for all human-readable text. Technical identifiers, file paths and the JSON keys stay as they are.
- Every `finding` needs a file. A finding without a location does not exist.
- Do not pad. Fifteen honest issues beat forty padded ones. If the code base is in good shape in some area, that area produces no issue.
- Never invent a line number. Take it from `facts.json` or from reading the file.
- If `facts.json` shows a high count but the locations turn out to be harmless, say so explicitly in an issue with low severity, so that the number is explained rather than left hanging.
