# dump selection plugin by deroko of ARTeam

Adds ability to dump selected bytes from IDA which can be easily
added to python/C/gas/tasm/nasm/masm.

Run plugin, select in disassembly what you want to be dumped, and
press one of available options. You will get in IDA output window
code ready to be used in one of mentioned languages.

Bye default plugin binds to **Ctrl+h** but you may change that easily.
Also plugin starts in full windows mode, but you may drag it down to 
the output window for convenience.

Example:

**dump py**
```
raw_data =  "\x45\x31\xc9\x45\x31\xc0\x31\xc9\x31\xd2\x48\x89";
raw_data += "\xe5";
```

**dump c**
```
unsigned int  raw_data_len = 13;
unsigned char raw_data[] = {
        0x45, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x31, 0xd2, 
        0x48, 0x89, 0xe5, 
};
```

**dump c asm** or **WTF mode** which also gives instruction as comment so it's 
easier to remember what was pattern for:

```
unsigned char raw_data[] = {
        0x45, 0x31, 0xc9,                                       // xor     r9d, r9d
        0x45, 0x31, 0xc0,                                       // xor     r8d, r8d
        0x31, 0xc9,                                             // xor     ecx, ecx
        0x31, 0xd2,                                             // xor     edx, edx
        0x48, 0x89, 0xe5                                        // mov     rbp, rsp
};
```

**dump gas**:
```
.byte                   0x45, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x31, 0xd2, 0x48, 0x89
.byte                   0xe5
```

**dump masm** - produces masm/tasm/nasm compatible byte array:
```
db                      045h, 031h, 0c9h, 045h, 031h, 0c0h, 031h, 0c9h, 031h, 0d2h, 048h, 089h
db                      0e5h
```

