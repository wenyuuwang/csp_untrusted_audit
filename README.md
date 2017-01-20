# csp_untrusted_audit

simulation and tests for research

## How to build JARs
- csp: compile source code in 'csp' folder and put the .class files in 'makeJAR' folder，then type: jar cvfm makeCSP.jar manifest.mf ./ to make JAR 
- user: compile source code in 'user' folder and put the .class files in 'makeUserJAR' folder, then type: jar cvfm makeUser.jar manifest.mf ./ to make JAR
- owner: configurations to specify blocks or acls to prepare for encryption and upload

## Folder Contents Summary
- makeJAR：including all .class files, block_index_list and the enrypted acl， with a manifest
- makeUserJAR: including all class files，with manifest
- attest: storage for attestations generated so far
- blocks: blocks that csp will import, encrypted and signed
- blocks_pre: to modify files in 'blocks' folder. Files in this folder will cover those with same name in 'blocks' folder
- blockID.txt text_url.txt request.txt permission.txt: example of format
- privatekey.dat and pubkey.dat: a pair of keys for attestation encryption（details in .class RSAen in 'csp' folder）
