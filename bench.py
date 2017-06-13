import timeit
import functools

import rsa
import prime

PRP = 0x13c6ff366eb6f235cccce9bc3a4f8a2f0f36360219ac9e9b6bd3b59c439c45bfa8b33ceaa369adf26603fc6df524ae1216d61d8bad6b08af31d50bb310cac456ff2264a06f60898d66a61bcc4012e9e0b9d8a7dd70412513dbd7cbea4b85aede5a8ee94012657eb2686c5bf92d8cd089c3de49ccc5b25e75de326357449d9df31
JUNK = (b'.bNMl89:..YPF&+/:lmqCGH.AZMR"?[SI_S^>Z%1M9co!EZJb#!+2M{0J[:YV#%.#?E!-=%6Ux5Y'
        b'p+A..L`.p#UPL+$.9>*[Vb<#Qb@..2wJ.?ECvo%]}*/`1NF|_>[r7W3=P6oD,9(O3UL|09~y)z3s'
        b'#*)Fe]dvI</"N0Cy8@#^<`xF6xenvO+-]=:46eAH@fz3H(r}rF]9L)O].!3Tu+.iYU2g(Y""d}MO'
        b'E^}O^YHe<yG#pXi*eNG+cn"CjDN/a&o]U`ZxQ`i1.6!VK!8PU-8`"[x.a$8&3$Q}ao#g/-^&A=!a'
        b'y/$za949W2C?]Xmtm371";7vO.+h^cE33(!s6Rf-<)[)+2jv,aIDX-#~ZGSHMm31[)G.NA35xO#}'
        b'b"_H{}^x7n*T-@W:@Q5#H/0$#/AO;htj)aO91WOL1{,+&-<}AF@.r)y-QECSv6E16[U[)],_}FDh'
        b'-5uYlRuG&]].gR$#Vmm:O/D%_ek,A^wa#K6dZ<gad<2]n!Hw>-5[>Fy3awK9/E-m.H,o/u(&TGM#'
        b'1I;|qq!v-e/1a(Sy&R@>N9+B]wYN"&$!%saC}@.y?0~])&TH#ZVpiN?MD-AH"#H=J5*)rE^i3S0{'
        b'>QRa7^zJ5$2KB<z-G"G($u5}N^mH3nkq$p$5.CW2b]|)YnL*m?v0_4WLV(W*/"1P-/*$<l,CUo,S'
        b'I~XN#.MBCyE-}VjRo^~2pQlW]Wn7,3PV6Q.M2:W>OFsLBYu:VwM-7mU!]e&R^?CJDh3a^r*=a"TO'
        b'YO#b|I<No`O-M#N5YEM20eIC#OKo,#A]C"V(P@-cHV!9tzrI};^rF`3rgf4&W@>928UvEb;G9#0F'
        b'^*o]PS6%~18s7KO)x?bTS@]#k#Vz2k7JF#TjK("6uw;A%%_S/{"MZ,Wa#L@WI{jOfSF@$8&U[S.['
        b'k1/N7_W7.TVN4gF`K4]P?|6DDgRYW$?#L1ILnR0E`fit%FE4FJ$a@F"Rr|6bbJfMZ.0_Qd#ymRG-'
        b'e6kYvC%EPdYAy9MaM.1|]Q|_HiG>:WD&xbIT')

def prow(*row):
    print(' %-23s | %s' % row)

def keygen(bits=1024):
    global key
    key = rsa.RSAKey(bits=bits, e=PRP)

def enc():
    global e
    e = rsa.RSA(key).encrypt_data(JUNK)

def dec(useCRT=True):
    k = key if useCRT else key.simplify()
    rsa.RSA(k).decrypt_data(e)

prow('Title', 'Time')
print('-' * 24 + '-+-' + '-' * 24)

prow(
    'is_probable_prime',
    timeit.timeit(lambda: prime.is_probable_prime(PRP, 15, 30), number=50)
)

prow(
    'RSAKey(bits=1024)',
    timeit.timeit(functools.partial(keygen, 1024), number=10)
)

prow(
    'RSAKey(bits=2048)',
    timeit.timeit(functools.partial(keygen, 2048), number=3)
)

prow(
    'encrypt data',
    timeit.timeit(enc, number=50)
)

prow(
    'decrypt data (CRT)',
    timeit.timeit(dec, number=50)
)

prow(
    'decrypt data (no CRT)',
    timeit.timeit(functools.partial(dec, False), number=50)
)
