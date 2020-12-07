'''
𝑐^d ≡ (𝑚^𝑒)^𝑑 ≡ 𝑚^𝑒𝑑 ≡ 𝑚 mod 𝑁.
帧数据的数据格式如下，其中数据都是 16 进制表示，结构:1024bit模数N | 1024bit加密指数e | 1024bit密文m^e mod N。
每次加密最多 8 个明文字符
由于 Alice 初次使用该软件，可能会重复发送某一明文分片。
'''
import binascii

import libnum
import gmpy2
from Crypto.Util.number import long_to_bytes


def if_N_the_same(n,c,e):#寻找模数相同的帧，假设加密的明文相同，用共模攻击求明文
    listn = list.copy(n)
    listc = list.copy(c)
    liste = list.copy(e)
    for i in range(len(listn)):
        listn[i] = '0x' + str(listn[i])
        listn[i] = int(listn[i], 16)
        listc[i] = '0x' + str(listc[i])
        listc[i] = int(listc[i], 16)
        liste[i] = '0x' + str(liste[i])
        liste[i] = int(liste[i], 16)
    for i in range(len(listn)-1):
        for j in range(i+1,len(listn)):
            if(listn[i]==listn[j]):
                print('They are the same',i,',',j,':',listn[i])
                assert (libnum.gcd(liste[i], liste[j]))
                _, s1, s2 = gmpy2.gcdext(liste[i], liste[j])  # 扩展欧几里得算法
                # 若s1<0，则c1^s1==(c1^-1)^(-s1)，其中c1^-1为c1模n的逆元。
                if s1 < 0:
                    s1 = -s1
                    listc[i] = gmpy2.invert(listc[i], listn[i])
                if s2 < 0:
                    s2 = -s2
                    listn[j] = gmpy2.invert(listc[j], listn[i])
                print('m of Frame', i ,'and', j ,'is:', pow(listc[i], s1, listn[i]) * pow(listc[j], s2, listn[i]) % listn[i])
                return pow(listc[i], s1, listn[i]) * pow(listc[j], s2, listn[i]) % listn[i]
    print('end of the function')


def if_e_small(e):#寻找低加密指数，e=3
    print('Looking for low encryption index 3')
    liste = list.copy(e)
    low_index=[]
    for i in range(len(liste)):
        a = '0x' + str(liste[i][255])
        a = int(a, 16)
        if (a == 3):
            print('e of Frame', i, 'is 3')
            low_index.append(i)
    print('end of the function')
    return low_index
def if_e_small_(e):#寻找低加密指数，e=5
    print('Looking for low encryption index 5')
    low_index=[]
    liste = list.copy(e)
    for i in range(len(liste)):
        a = '0x'+str(liste[i][255])
        a = int(a,16)
        if (a == 5):
            print('e of Frame', i, 'is 5')
            low_index.append(i)
    print('end of the function')
    return low_index

def low_decryption(n,c):
     listn = list.copy(n)
     listc = list.copy(c)
     i=0
     listc = '0x' + str(listc)
     listn = '0x' + str(listn)
     listc = int(listc,16)
     listn = int(listn,16)
     while 1:
        if(gmpy2.iroot(listc + i*listn, 3)[1]==1):
            print(gmpy2.iroot(listc+i*listn, 3))
            break
        i=i+1

def broadcast_attack(list,listn,listc):#采用低加密指数广播攻击对e=5的帧进行破解

    for i in range(len(list)):
        listn[list[i]] = '0x' + str(listn[list[i]])
        listn[list[i]] = int(listn[list[i]], 16)
        listc[list[i]] = '0x' + str(listc[list[i]])
        listc[list[i]] = int(listc[list[i]], 16)
    N = 1
    for i in range(len(list)):
        N *= listn[list[i]]
    result = 0
    for i in range(len(list)):
        m = N // listn[list[i]]
        m_ = gmpy2.invert(m,listn[list[i]])
        m = m*m_*listc[list[i]]
        result += m
    m3 = result % N
    m3 = gmpy2.iroot(m3, 5)
    return m3[0]

def broadcast_attack3(list,listn,listc):#采用低加密指数广播攻击对e=5的帧进行破解

    for i in range(len(list)):
        listn[list[i]] = '0x' + str(listn[list[i]])
        listn[list[i]] = int(listn[list[i]], 16)
        listc[list[i]] = '0x' + str(listc[list[i]])
        listc[list[i]] = int(listc[list[i]], 16)
    N = 1
    for i in range(len(list)):
        N *= listn[list[i]]
    result = 0
    for i in range(len(list)):
        m = N // listn[list[i]]
        m_ = gmpy2.invert(m,listn[list[i]])
        m = m*m_*listc[list[i]]
        result += m
    m3 = result % N
    m3 = gmpy2.iroot(m3, 3)
    return m3[0]


def if_gcd(n,liste,listc):
    print('utilize common factors---------------------------------------')
    listn = list.copy(n)
    e = list.copy(liste)
    c= list.copy(listc)
    common = []
    m = []
    for i in range(len(listn)):
        listn[i] = '0x' + str(listn[i])
        listn[i]= int(listn[i], 16)
        e[i] = '0x' + str(e[i])
        e[i] = int(e[i], 16)
        c[i] = '0x' + str(c[i])
        c[i] = int(c[i], 16)
    for i in range(len(listn)):
        for j in range(len(listn)):
            if(i!=j):
                gcd = gmpy2.gcd(listn[i],listn[j])
                if(gcd!=1 and gcd!=listn[i]):
                    print('Frame',i,'and Frame',j,'have a common factor')
                    print('gcd:',gcd)

                    common.append(i)
                    common.append(gcd)
                   # common.append(j)
    for i in range(0,len(common),2):
        q = listn[common[i]] // common[i+1]
        phi_n = (common[i+1] - 1) * (q - 1)
        d = gmpy2.invert(e[common[i]], phi_n)
        m_= gmpy2.powmod(c[common[i]], d, listn[common[i]])
        m.append(int(m_))
    print('end of the function')
    return m

def pp1(n):
    B=2**20
    a=2
    for i in range(2,B+1):
        a=pow(a,i,n)
        d_=gmpy2.gcd(a-1,n)
        if 1< d_ <n:#如果d=1或者d=n则要重新寻找d
            q=n//d_
            n=q*d_
    return d_
def pollard_resolve(i,n,liste,listc):
    print('utilize pollard p-1---------------------------------')
    listn = list.copy(n)
    e = list.copy(liste)
    c = list.copy(listc)
    #print(listn[i], c[i], e[i])
    N = int(listn[i], 16)
    c = int(c[i], 16)
    e = int(e[i], 16)
    # N = listn[index_list[i]]
    # c = c[index_list[i]]
    # e = e[index_list[i]]
    p = pp1(N)
    print("p of " + str(i) + " is : " + str(p))
    q = N // p
    print("q of " + str(i) + " is : " + str(q))
    phi_of_frame = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi_of_frame)
    m = gmpy2.powmod(c, d, N)
    print('m of Frame i is:',m)
    #plaintext.append(binascii.a2b_hex(hex(m)[2:]))
    return m

def Fermat(i,n,listc,liste):
    global p, q
    print('utilize Fermat |p-q|---------------------------------')
    listn = list.copy(n)
    e = list.copy(liste)
    c = list.copy(listc)
    N = int(listn[i], 16)
    c = int(c[i], 16)
    e = int(e[i], 16)
    x = gmpy2.iroot(N, 2)[0]
    for j in range(1000000):
        x += 1
        if gmpy2.iroot(x ** 2 - N, 2)[1] == 1:
            y = gmpy2.iroot(x ** 2 - N, 2)[0]
            p = x + y
            q = x - y
            break
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m=pow(c, d, N)
    #m = long_to_bytes(pow(c, d, N))
    print('m of Frame',i,' is:',m)
    return m

def print_l(string, list):
    print(string, ':--------------------------------------------------------------------------------------------------------')
    for i in range(len(list)):
         print('Frame',str(i), '  ', list[i])


#求出每个帧中的N，e和c
m, N, e, c = [], [], [], []
filename = ['Frame' + str(i) for i in range(21)]
for i in range(21):
    fd = open(filename[i], 'r')
    m.append(fd.read())
    fd.close()
for frame in m:
    N.append(frame[0:256])#N
    e.append(frame[256:512])#e
    c.append(frame[512:768])#C
print('****************************************************WELCOME***********************************************')

print_l('N=', N)
print_l('e=', e)
print_l('c=', c)

#
# pp_1_index = [2,6,19]
# plaintext = []
# for i in range(len(pp_1_index)):
#     mm = pollard_resolve(pp_1_index[i],N,e,c)
#     plaintext.append(mm)
# for i in range(len(plaintext)):
#     m0 = hex(plaintext[i])
#     m0 = m0[114:]
#     print(binascii.a2b_hex(m0))
# #############
# fermat_index = [10,14]
# for i in range(len(fermat_index)):
#     mm = Fermat(fermat_index[i],N,c,e)
#     plaintext.append(mm)


##############
# m_gcd = if_gcd(N,e,c)
# m1 = m_gcd[0]
# m18 = m_gcd[1]
# print('m of Frame0 :',m_gcd[0])
# print(m1)
# m1 = hex(m1)
# m1 = m1[114:]
# print(binascii.a2b_hex(m1))
# print('m of Frame18 :',m_gcd[1])
# print(m18)
# m18 = hex(m18)
# m18 = m18[114:]
# print(binascii.a2b_hex(m18))

#print_l('N=', N)
#对e=3的分组7，11，15进行攻击，无结果
'''
low_index1 = if_e_small(e)
print('list of e=3:',low_index1)

for i in range(len(low_index1)):
    print('m of Frame',low_index1[i],'is:')
    low_decryption(N[low_index1[i]],c[low_index1[i]])
'''
#再对e=5的分组进行低加密指数攻击
# low_index2 = if_e_small_(e)
# print('list of e=5:',low_index2)
# m3 = broadcast_attack(low_index2,N,c)
# print('m of Frame3 :',m3)
# m3 = hex(m3)
# m3 = m3[114:]
# print(binascii.a2b_hex(m3))
#
# plaintext.append(m3)
# print('-----------------------')
# m0 = if_N_the_same(N,c,e)
# plaintext.append(m0)
# print('-----------------------')
# m0 = hex(m0)
# m0 = m0[114:]
# print(binascii.a2b_hex(m0))
##########
