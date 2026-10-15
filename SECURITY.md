# Security and data-integrity reports

Use GitHub private vulnerability reporting if available for a security defect.
Do not post exploit details, disk images or personal file data in a public issue.
Ordinary bugs may be reported in Issues using a generated-image reproduction.

For a suspected storage failure, stop writes and retain logs. Do not keep
retrying writes on a failing filesystem. HFS Bridge does not perform repairs.
Only the newest early-access release is currently maintained; there is no
production support or recovery guarantee.
