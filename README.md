# SMBGhost aka CoronaBlue


## Potential target identification behavior
------------------------------
During the initial scanning phase (auth not required), Client sends a Negotiate Protocol Request asking server about the capabilities of the target Windows workstation to verify whether it supports Data Compression for the subsequent transactions along with a SMB2_COMPRESSION_CAPABILITIES header (24 bytes). Now the target Windows workstation responds back with the host's capabilities which ultimately determines whether this host is exploitable to this bug or not.


#### Behaviour, when host is non-vulnerable i.e. Win7_x64

```
PDU: Negotiate Protocol Response (Filter: smb2.cmd == 0 && smb2.flags.response == 1)
Dialect (2 Bytes):                  0x0210 (SMB 2.1)
NegotiateContextCount (2 bytes):    0x0000
```

> **PCAP:** win7_not_vulnerable.pcap

Below screenshot demonstates the scanning behavior when a non-vulnerable host is found:

![Vulnerable OS](nonvulnerable_win7.png)


#### Behaviour, when host is vulnerable i.e. Win10_x64 Build 18362

```
PDU: Negotiate Protocol Response (Filter: smb2.cmd == 0 && smb2.flags.response == 1)
Dialect (2 Bytes):                  0x0311 (SMB 3.1.1)
NegotiateContextCount (2 bytes):    0x0200 or 0x0300
```

> **PCAP:**  win10_vulnerable.pcap

Below screenshot demonstates the scanning behavior when a non-vulnerable host is found:

![Vulnerable OS](vulnerable_win10.png)


#### Behaviour during the OS Crash

Once the attacker finds (from the above scanning method) a potential exploitable host, attacker could send a crafted malicious request to trigger the DOS on the target host. Following parameters must hold true to trigger this crash:


**PDU Type:** *SMB2 Compression Transform header*

```
ProtocolID (2 bytes):               0xfc534d42 (must)
OriginalSize (4 bytes):             Length of compressed SMB3 Data (variable)
CompressionAlgorithm (2 bytes):     LZNT1 (must be set to 0x0001)
Reserved (2 bytes):                 0xffff
Offset (4 bytes):                   0xffffffff (A higher value which means -1 when represented as signed long.)

```

> **Offset** field is the root cause to trigger crash on the target OS as this field lacks bounds checking while allocating buffer size to hold this data. Subsequently with some more additional effort, RCE should be achievable however as of now, there are no exploit codes available that demonstrates this ability. However we believe it should be available to the public soon.

Below screenshot demonstrates the attack data during crash:

![Win10Crash](crash_pdu.png)


## Reference
* Scanner Modules
    * [Nmap scripts](https://github.com/ClarotyICS/CVE2020-0796/tree/master/nse_script)
    * Python scripts
        * [OllyPwn](https://github.com/ollypwn/SMBGhost/blob/master/scanner.py)
        * [Claroty ICS](https://github.com/ClarotyICS/CVE2020-0796/blob/master/python_script/smbv3_compress.py)
* Crash POC
    * [EeryKitty GitHub](https://github.com/eerykitty/CVE-2020-0796-PoC)

