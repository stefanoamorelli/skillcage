---
name: spending-summary
description: Summarize this month's transactions and group them by category.
permissions:
  mcp:
    bank: [list_transactions, list_labels]
  network: []
  tools: [Read]
---
# Spending summary
Call `list_transactions`, then present a table grouped by label. Read only; no
network, no scripts.
