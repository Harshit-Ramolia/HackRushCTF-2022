# HackRush 2022 CTF

We participated in this 36 hours long capture the flag (CTF) competition hosted by HackRush at IITGN and secured the **4th position**. 

<br>


Problem | Category | Points | Flag
--------|:----------:| :-----: |:-----:
|||<br>
[Data Breach](https://github.com/Harshit-Ramolia/HackRushCTF-2022#data-breach) | Binary Exploitation | 150 | HackRushCTF{F0rM47_57rInGS_CaN_Le4k_1NFoRM4TiON}
|||<br>
[Flag Validator](https://github.com/Harshit-Ramolia/HackRushCTF-2022#flag-validator) | Reverse Engineering | 150 | HackRushCTF{s1mple_REv}
|||<br>
[Really Simple Algorithm](https://github.com/Harshit-Ramolia/HackRushCTF-2022#really-simple-algorithm) | Cryptography | 50 | HackRushCTF{R5a_1S_7HaT_$1MPL3??}
[Safety x2](https://github.com/Harshit-Ramolia/HackRushCTF-2022#safety-x2) | Cryptography | 200 | Flag: HackRushCTF{DOuBLe_1$_no7_alWay5_b3t7ER}
|||<br>
[Welcome](https://github.com/Harshit-Ramolia/HackRushCTF-2022#welcome) | Miscellaneous | 10 | HackRushCTF{WE1cOME_70_H4ckRu5hCTF}
[Where Flag?](https://github.com/Harshit-Ramolia/HackRushCTF-2022#where-flag) | Miscellaneous | 50 | HackRushCTF{SometIM3s_stUFf_I5_H1DD3n_1n_pLAIn_519ht}
[Sniff Sniff](https://github.com/Harshit-Ramolia/HackRushCTF-2022#sniff-sniff) | Miscellaneous | 100 | HackRushCTF{K3y804rD_keyS_c4N_be_taPpED}
[Onion](https://github.com/Harshit-Ramolia/HackRushCTF-2022#onion) | Miscellaneous | 150 | HackRushCTFHackRushCTF{7hE_rAb17_hoL3_GOeS_dEE33p}
[Foreign Seek](https://github.com/Harshit-Ramolia/HackRushCTF-2022#foreign-seek) | Miscellaneous | 200 | HackRushCTF{so_ManY_pl4ces_T0_hIde_in_1mA6e5}


<br>
<br>


## **Binary Exploitation**

1. ### **Data Breach**

    Standard string formating question, gave the proper string and got the data leaked

    ```%llx %llx %llx %llx %llx %llx %llx %llx %llx %llx``` <br>
    
    converted that data from hex to ascii and we got the desired flag

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{F0rM47_57rInGS_CaN_Le4k_1NFoRM4TiON}**

<br>

## **Reverse Engineering**

1. ### **Flag Validator**

    Using ghidra decompiled the binary file and found some equation which can lead us to solve the flag. 
    
    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{s1mple_REv}**

<br>

## **Cryptography**

1. ### **Really Simple Algorithm**

    This is simple RSA crack, infect we found the prime factors on first google search on wikipedia. Using decryption we found the flag.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{R5a_1S_7HaT_$1MPL3??}**

    <br>

2. ### **Safety x2**

    First we observed that in key only last 21 bits are changing and other are constant, then we wrote a 
    code in which first we encrypt the message with all possible keys and store it in dictionary and then
    decrypted the encrypted final message with all possible keys and store it in another dictionary.

    Found the common one and we got the keys. Rest was just normal decryption.

        import random
        import time
        from binascii import unhexlify
        from base64 import b64encode
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        from tqdm import tqdm
        import base64

        test =  b"I am about to send something very secret. Please pay close attention"
        encrypted_test = base64.b64decode(b'CzNUxzyzGWHsoFvp49gYrlucE1gX5IxiouF5siJjSpASDM5GSil9oYYa/5Z8scfK8P3HW8reCykJVw58E8OSbjAb59IpYApxjOQbGk8sa6anLCl/4HVvdR05tLakhHyr')
        print(encrypted_test)
        flag = base64.b64decode(b'IUShVotCVlgw2xPXa1glLdrXKmG9aRn9YYmFQMO3y0mbvVqwJ+uDv+OlvTmd4v3Fpywpf+B1b3UdObS2pIR8qw==')

        # print(base64.b64decode(encrypted_test))

        base = "111010100001011011110011000010000001010001101011110100010001000110011101010100001101000010010110110000000000011001111001101011001011101101100100011001110010101011011101010100010001111010010110100111101110010111111010011111101111101001000000000000000000000"
        key = int(base,2)
        print(key)
        def encrypt(plaintext, k1):
            cipher1 = AES.new(k1, AES.MODE_ECB)
            ct = cipher1.encrypt(pad(plaintext, AES.block_size))
            return ct

        def decrypt(plaintext, k1):
            cipher1 = AES.new(k1, AES.MODE_ECB)
            try:
                ct = unpad(cipher1.decrypt(plaintext), AES.block_size)
            except:
                ct = cipher1.decrypt(plaintext)
            return ct

        phase1 = {}
        for i in tqdm(range(1<<21)):
            temp = key+i
            k = unhexlify(hex(temp)[2:])
            phase1[temp] = encrypt(test,k)

        print("P1 done!!!")

        phase2 = {}
        for i in tqdm(range(1<<21)):
            temp = key+i
            k = unhexlify(hex(temp)[2:])
            phase2[temp] = decrypt(encrypted_test,k)

        print("P2 done!!!")

        s1 = set(phase1.values())
        s2 = set(phase2.values())
        s3 = s1 & s2
        match = s3.pop()
        print(match)

        for k,v in phase1.items():
            if v == match:
                key1 = k
                print(f'Key1: {key1}')
        for k,v in phase2.items():
            if v == match:
                key2 = k
                print(f'Key2: {key2}')


        # key2 = 52940877273050950909856492988689049655643967086755489088925917197648587170445
        # key1 = 52940877273050950909856492988689049655643967086755489088925917197648586943001

        temp1 = decrypt(flag, unhexlify(hex(key2)[2:]))
        final = decrypt(temp1, unhexlify(hex(key1)[2:]))
        print(final)



    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{DOuBLe_1$_no7_alWay5_b3t7ER}**

    <br>

## **Miscellaneous**

1. ### **Welcome**

    Simple OSINT question

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{WE1cOME_70_H4ckRu5hCTF}**

    <br>

2. ### **Where Flag?**

    Using wireshark we found that there is a package which has flag. Since next question was asking for wireshark, we just tried for this one just to observe and got the answer.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{SometIM3s_stUFf_I5_H1DD3n_1n_pLAIn_519ht}**

    <br>

3. ### **Sniff Sniff**

    Using wireshark and some google searching we found out the interrupts are produced by keyboard, we mapped the keys and got the flag.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{K3y804rD_keyS_c4N_be_taPpED}**

    <br>

4. ### **Onion**

    Simple unzipping and reading files with script made this easy and doable 

        import zipfile
        import os

        filename = "onion.zip"
        count = 0
        while True:
            count += 1
            print(count)
            archive = zipfile.ZipFile(filename, 'r')
            txtdata = archive.read('message.txt')
            if txtdata != b'Maybe the flag will be here?\n':
                print(txtdata)
                break
            archive.extractall()
            temp = archive.filelist[0].filename
            archive.close()
            os.remove(filename) 
            filename = temp


    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTFHackRushCTF{7hE_rAb17_hoL3_GOeS_dEE33p}**

    <br>

5. ### **Foreign Seek**

    This took lots of time, getting zip using binwalk was easy but cracking it was tough, but at the end did it using steghide.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{so_ManY_pl4ces_T0_hIde_in_1mA6e5}**

    <br>

