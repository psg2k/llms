def mul_inv(a,m):
  r1,r2=a,m
  s1,s2=1,0
  while r2>0:
    q=r1//r2
    r=r1-q*r2
    s=s1-q*s2
    r1=r2
    r2=r
    s1=s2
    s2=s
  if r1!=1:
    return None
  if s1<0:
    s1+=m
  return s1

def affine(pt,k1,k2,mode="encrypt"):
  inv=mul_inv(k1,26)
  if inv is None:
    print("thats stupid")
    return
  lower_pt=pt.lower()
  res=""
  for char in lower_pt:
    if char.isalpha():
      if mode=="encrypt":
        ct=((ord(char)-ord('a'))*k1 +k2)%26
      else:
        ct=((ord(char)-ord('a')-k2)*inv)%26
      res+=chr(ct+ord('a'))
    else:
      res+=char
  if pt.isupper():
      return res.upper()
  print("res:",res)
  return res

enc=affine("this is me",15,5,"encrypt")
dec=affine(enc,15,5,"decrypt")