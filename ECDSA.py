import random

#y^2 = x^3 + ax + b (mod p)
class EllipticCurve(object):
    def __init__(self, a, b, mod):
        self.a = a
        self.b = b
        self.mod = mod

class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y

# inverse
def mod_inverse(a, m):
    for x in range(1, m):
        if ((a % m) * (x % m)) % m == 1:
            return x
    return -1

# add P + R = Q
def point_addition(p, q, curve):

    if p is None: # Identity element
        return q
    if q is None: # Identity element
        return p
    # print("p,q: (", p.x, ",", p.y, "), (", q.x, ",", q.y, ")")
    if p.x == q.x and p.y == -q.y % curve.mod: # p + (-p) = 0
        return None
    if p == q:
        lam = (3 * p.x ** 2 + curve.a) * mod_inverse(2 * p.y, curve.mod) % curve.mod
    else:
        lam = (q.y - p.y) * mod_inverse(q.x - p.x, curve.mod) % curve.mod
    x3 = (lam ** 2 - p.x - q.x) % curve.mod
    y3 = (lam * (p.x - x3) - p.y) % curve.mod
    return Point(x3, y3)

# mul 3 * P = P + P + P
def point_multiplication(p, n, curve):
    result = None
    addend = p
    # print(n)
    while n:
        if n & 1:
            result = point_addition(result, addend, curve)
        addend = point_addition(addend, addend, curve)
        n >>= 1
    return result

# key generate alg
def generate_keypair(curve, g):
    private_key = random.randint(1, curve.mod - 1) #1 to mod
    public_key = point_multiplication(g, private_key, curve)
    return private_key, public_key

# sign
def ecdsa_sign(m, curve, g, private_key):
    while True:
        k = random.randint(1, curve.mod - 1)
        # print("k = ", k)
        p1 = point_multiplication(g, k, curve)
        # p1 = point_multiplication(g, private_key, curve)
        r = p1.x % curve.mod
        if r == 0:
            continue
        s = (mod_inverse(k, curve.mod) * (m + private_key * r)) % curve.mod
        if s == 0:
            continue
        # print("Here: ",r,s)
        return r, s

# verify
def ecdsa_verify(m, signature, curve, g, public_key):
    r, s = signature
    # print("Here2: ", r, s)
    w = mod_inverse(s, curve.mod) #w = s^-1 mod n
    u1 = (m * w) % curve.mod #hash(m)
    u2 = (r * w) % curve.mod
    p1 = point_multiplication(g, u1, curve)
    p2 = point_multiplication(public_key, u2, curve)
    p = point_addition(p1, p2, curve)
    return p.x % curve.mod == r

# y^2 = x^3 + ax + b (mod p)
curve = EllipticCurve(a=2, b=2, mod=17)

# G
g = Point(5, 1)

# generate key
private_key, public_key = generate_keypair(curve, g)

# message
m = 10
signature = ecdsa_sign(m, curve, g, private_key)
# print("Here: ",signature, " Type: ",type(signature))

print(ecdsa_verify(m, signature, curve, g, public_key))
