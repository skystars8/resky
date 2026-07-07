# R E S K Y 001

Not made for serious use- unless you are serious about using something not made for serious use. 

a- XChaCha-poly1305 hard coded key, encrypts in memory, no streaming 
Uses XChaCha20Poly1305 from the chacha20poly1305 crate
Correctly uses XNonce (24-byte nonce)
Nonce is randomly generated and stored in the header
Header is passed as AAD (Authenticated Associated Data)
This is the proper way to use XChaCha20-Poly1305 (sort of lol) Ai can easily 
make it take a key file or password input via argon2id. This is a starter kit- use as is for informal 
encryption or have ai change it. 

b- AES256-GCM-SIV hard coded key, encrypts in memory, no streaming
Uses Aes256GcmSiv from the aes-gcm-siv crate
Correctly uses regular Nonce (12-byte nonce)
Nonce is randomly generated and stored in the header
Header is passed as AAD
This is the proper way to use AES-256-GCM-SIV (sort of lol) Ai can easily 
make it take a key file or password input via argon2id. This is a starter kit- use as is for informal 
encryption or have ai change it. 

c- Xor transformer / otp. Versatile. 

d- password XChaCha-poly1305 - (currently different ai audits argue with each-other about minor issues, overall a very solid start tho. this is in dev mode till ai gets more consistent at auditing the details. 



