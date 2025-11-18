Folder
- merkletree: store the complete merkle tree
- merkleOps: merkle tree involved Module
- Logs: collection of log's meta data, raw, hashed(not work yet)

File
- LogServer: receive the log, accumulate, commit the merkle tree construct
- LogClient: simulate the log sending to the server

Blockchain set up (Ethereum: Ganache)
- Downland Ganache
- Lunch the quick set up in Ganache
- Open Remix IDE on the web browser
- Upload file verify_test on Remix IDE
- Select the solidity complier version 0.6.12
- complie the verify_test
- Find the contract address, ABI(on the complie details)
- Replace the these value on file test-import.js, block_test
  
Demo instruction
- javac LogServer.java: create java class
- java LogServer: open the Server
- javac LogClient.java: create java class
- java LogClient: insert Log to the server. This will create
  - epoch_*log type*_*epoch No*.txt,
  - logs_batch_*Epoch No*_LogMetadata.txt,
  - merklebatch_*Epoch No*
  - commit the hash to blockchain
- Examine the logs_batch_*.json to see the raw log
- Execute command to verify log on power shell:
  - Invoke-WebRequest -Uri http://localhost:8080/verify -Method POST -ContentType "application/json" -Body '{"rawLog":{"id":1,"timestamp":176396169628,"Type":"firewall","message":"Single log 1"}}'
  - Replace the {"id":1,"timestamp":176396169628,"Type":"firewall","message":"Single log 1"} with raw log
