Hi, I've already built a working reference MVP for exactly this brief: https://github.com/<you>/pharmatrace

What's in it today: role-based access (regulator / manufacturer / distributor / pharmacy), GS1-style unit IDs,
end-to-end custody transfer, a hash-chained audit ledger that detects any edited or deleted record, a public
verification endpoint for patients, ML-based counterfeit detection (cloned serials, resellers, fake batches),
and n8n automation that alerts regulators hourly. It ships with 24 automated tests, including OWASP API Top 10
security tests, plus CI with SAST and dependency scanning.

My background: bioinformatics + Python + data science + penetration testing, so I build health-data systems
that are both analytically sharp and secure by default.

Proposed plan: 4 weekly milestones (auth & registry, traceability & ledger, analytics, dashboard + final pentest).
Happy to walk you through a live demo.
