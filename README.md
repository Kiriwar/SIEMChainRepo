Folder
- merkletree: store the complete merkle tree
- merkleOps: merkle tree involved Module
- Logs: collection of log's meta data, raw, hashed(not work yet)

File
- LogServer: receive the log, accumulate, commit the merkle tree construct
- LogClient: simulate the log sending to the server

Demo instruction
- Execute LogServer.java
- Execute LogClient.java to insert Log to the server. This will create
  - epoch_*log type*_*epoch No*.txt,
  - logs_batch_*Epoch No*_LogMetadata.txt,
  - merklebatch_*Epoch No*
- Examine the logs_batch_*.json to see the raw log
- Execute command to verify log:
  - Invoke-WebRequest -Uri http://localhost:8080/verify -Method POST -ContentType "application/json" -Body '{"rawLog":{"id":1,"timestamp":176396169628,"Type":"firewall","message":"Single log 1"}}'
  - Replace the {"id":1,"timestamp":176396169628,"Type":"firewall","message":"Single log 1"} with raw log
