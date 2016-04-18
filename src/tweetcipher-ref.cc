// 
// TweetCipher reference implementation:
// http://cybermashup.com/2013/06/12/tweetcipher-crypto-challenge/
// 
#include <stdint.h>
#include <stdio.h>
#define LOOP(n) for(i=0;i<n;++i)
#define W(v,n) ((uint64_t*)v)[n]
#define R(v,n)(((v)<<(64-n))|((v)>>n))
#define AXR(a,b,c,r) x[a]+=x[b];x[c]=R(x[c]^x[a],r);
#define G(a,b,c,d) {AXR(a,b,d,32) AXR(c,d,b,25) AXR(a,b,d,16) AXR(c,d,b,11)}
#define ROUNDS {for(r=6;r--;){LOOP(4) G(i,i+4,i+8,i+12) \
                              LOOP(4) G(i,(i+1)%4+4,(i+2)%4+8,(i+3)%4+12)}}

// $ echo smashup | ./tweetcipher  e kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk vvvvvvvvvvvvvvvv | ./tweetcipher d  kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk vvvvvvvvvvvvvvvv 

 
int main(int _,char**v){
  uint64_t x[16],i,c,r,f='e'==*v[1];
  LOOP(16)
    x[i]=i*0x7477697468617369ULL;
  LOOP(4) x[i]=W(v[2],i);
  LOOP(2) x[i+4]=W(v[3],i);
  ROUNDS;
  while((c=getchar())!=EOF){
    if(!f&&10==(x[0]^c)%256)return 0;
    putchar(x[0]^c);
    x[0]=c^(f?x[0]:x[0]&~255ULL);
    ROUNDS;
  }
  x[0]^=1;
  ROUNDS;
  LOOP(8) putchar(255&((x[4]^x[5])>>8*i));
  LOOP(8) putchar(255&((x[6]^x[7])>>8*i));
  return 0;
}
