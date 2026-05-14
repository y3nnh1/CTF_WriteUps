Structure of the badge: a fixed length plaintext that will be encrypted with AES in ECB mode. 
It consists of: "version"(2 bytes), "name"(30bytes), "issuer"(16bytes) and "role"(16 bytes), which makes up total size to be 64 bytes, which is 4 blocks of 16 bytes. 
The block is encrypted block by block using AES-ECB (ECB mode: block encrypted independently; is deterministic meaning same plaintext results in same ciphertexts;  blocks can be rearranged without detection. 
Determinism and the fact that it is rearrangeable without being detected makes ECB malleable by substituting blocks. 
The role (here visitor) is the entire block itself. 
To visualise, 4 blocks B1..B4: B1 (version 2B + first 14 bytes of name), B2(remaining 16 bytes of name), B3(issuer), B4(role).

if badge['issuer'] != 'MAC' or badge['role'] not in ['visitor', 'curator']:
            self.send('Badge rejected: invalid issuer or role.')
            return
            
here if I aim to obtain a badge where role = curator, I can "manipulate" it. 
As for the name and for the contents in each block B1...B4, one can choose any name, as long as they are 30 bytes, contains ONLY "curator" in B2. 
So the first 14 bytes of the name does not matter.
I chose: 
" name="              curator         " 
(B1 = all first 14 spaces) (B2 = curator + rest 9 spaces). 
The system encrypts and returns C = C1|C2|C3|C4 where C2 = Enc("curator") and C4 = Enc ("Visitor").  
Since ECB encrypts blocks independently, we can replace C4 with C2. So our new ciphertext C' = C1|C2|C3|C2.

Structure of control ticket: 
ticket_fields = {
            'version': '1.2.194.23',
            'target': 'logs',
            'cmd': 'read',
            'expires': expires.strftime('%d/%m/%Y %H:%M:%S')
        }. 
"version=1.2.194.23&target=" is 26 bytes long; following up is "logs" so, logs starts at offset 26 in plaintext. 
The ticket(ciphertext) format is nonce(8bytse) || ciphertext. 
CTR mode behaves like a stream cipher, meaning that flipping bits in the ciphertext results in predictable changes in plaintext after decryption. 
Since there is no integrity protection, CTR is malleable.

Here my goal is to "manipulate/modify" the "target = logs" into "target = flag". 
I know that logs starts at offset 26 in the plaintext and the transmitted ticket includes the none: offset = nonce + 26 = 8 + 26 = 34. 
Knowing Encryption scheme for CTR : c = m XOR keystream so m = c XOR keystream. 
One can change 
 -> ciphertext c' = c XOR Δ 
      -then m' = c' XOR keystream = c XOR Δ Xor key = m XOR Δ (chosen cipher text manipulation). 
Using this knowledge, I can compute Δ = "logs" XOR "flag". 
Now my new ciphertext c' = c XOR Δ. I apply it to the ciphertext at position 34-37 (34 = "l", 35 = "o", 36 = "g", 37 ="s").
After decryption it becomes m XOR Δ. Since plaintext = "logs", I have logs XOR logs  XOR flag = flag, while other fields remain unchanged. 
At the end the systems checks cmd == read and target == flag so it returns the flag.

