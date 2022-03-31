/*
The C reference implementation of the
block ciphers PAGES+ with 512 bit blocksize
for gcc compatible compilers.

Copyright 2015 by

Dieter Schmidt*/

#include <stdio.h>
#include <time.h>

#define INTLENGTH 128
#define NUMROUNDS 128 // 64,96, and 128 are possible
#define ROL(x,a) ((((x)<<(a))|((x) >>(INTLENGTH-(a)))))
#define ROR(x,a) ((((x)>>(a))|((x)<<(INTLENGTH-(a)))))
#define KEYLENGTH NUMROUNDS/8
#define ROTROUNDKEY 121
#define ROTROUNDDATA1 7
#define ROTROUNDDATA0 19
#define ROTROUNDDATA3 9
#define ROTROUNDDATA2 21

#define FORWARD

void encrypt (unsigned __int128 data[4],\
unsigned __int128 keys [2*NUMROUNDS]){

register unsigned long i;
register unsigned __int128 a,b,c,d;

	a=data[0];b=data[1];c=data[2];d=data[3];
	for (i=0;i<NUMROUNDS;i++){
		a=ROR(a,ROTROUNDDATA0);
		c=ROR(c,ROTROUNDDATA2);
		c^=d;
		b^=c;
		a^=b;
		b=ROL(b,ROTROUNDDATA1);
		d=ROL(d,ROTROUNDDATA3);
		a+=keys[2*i];
		b+=a;
		c^=b;
		c+=keys[2*i+1];
		d+=c;
	}
	data[0]=a;data[1]=b;data[2]=c;data[3]=d;
	return;
}

void decrypt (unsigned __int128 data[4],\
unsigned __int128 keys[2*NUMROUNDS]){

	register unsigned long i;
	register unsigned __int128 a,b,c,d;
	
	a=data[0];b=data[1];c=data[2];d=data[3];
	for (i=0;i<NUMROUNDS;i++){
		d-=c;
		c-=keys[2*NUMROUNDS-2*i-1];
		c^=b;
		b-=a;
		a-=keys[2*NUMROUNDS-2*i-2];
		d=ROR(d,ROTROUNDDATA3);
		b=ROR(b,ROTROUNDDATA1);
		a^=b;
		b^=c;
		c^=d;
		c=ROL(c,ROTROUNDDATA2);
		a=ROL(a,ROTROUNDDATA0);
	}
	data[0]=a;data[1]=b;data[2]=c;data[3]=d;
	return;
}

void expand_key(unsigned __int128 userkey[KEYLENGTH],\
unsigned __int128 keys [2*NUMROUNDS]){

unsigned long i,j;
unsigned __int128 data[4],a;

for (i=0;i<KEYLENGTH;i++) keys[i]=userkey[i];
	for (i=1;i<16;i++){
		a=keys[(i-1)*KEYLENGTH];
		a>>=(INTLENGTH-ROTROUNDKEY);
		for(j=0;j<(KEYLENGTH-1);j++){
			keys[i*KEYLENGTH+j]=(keys[(i-1)*KEYLENGTH+j]\
			<<ROTROUNDKEY)|(keys[(i-1)*KEYLENGTH+j+1]\
			>>(INTLENGTH-ROTROUNDKEY));
		}
	keys[i*KEYLENGTH+KEYLENGTH-1]=\
	(keys[(i-1)*KEYLENGTH+KEYLENGTH-1]\
	<<ROTROUNDKEY)|a;
	}
	data[0]=0;data[1]=0;data[2]=0;data[3]=0;
	for(i=0;i<(NUMROUNDS/2);i++){
		encrypt(data,keys);
		#ifdef FORWARD
			keys[4*i]=data[3];
			keys[4*i+1]=data[2];
			keys[4*i+2]=data[1];
			keys[4*i+3]=data[0];
		#else
			keys[2*NUMROUNDS-4-4*i]=data[3];
			keys[2*NUMROUNDS-4*i-3]=data[2];
			keys[2*NUMROUNDS-4*i-2]=data[1];
			keys[2*NUMROUNDS-4*i-1]=data[0];
		#endif
	}
	return;
}

int main(){

	unsigned __int128 data[4],userkey[KEYLENGTH],keys[2*NUMROUNDS];
	unsigned long i,j,k,l;
	time_t start,stop;
	double r;

	data[0]=0;data[1]=1;data[2]=2;data[3]=3;
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	printf ("Before encryption %20lx%20lx%20lx%20lx\n",i,j,k,l);
	for(i=0;i<KEYLENGTH;i++) userkey[i]=i;
	expand_key(userkey,keys);
	encrypt(data,keys);
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	printf("After encryption %20lx%20lx%20lx%20lx\n",i,j,k,l);
	decrypt(data,keys);
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	printf("After decryption %20lx%20lx%20lx%20lx\n",i,j,k,l);
	time(&start);
	for (i=0;i<1024*1024*16;i++) encrypt(data,keys);
	time(&stop);
	r=((double) 8192)/difftime(stop,start);
	printf("%20.10lf\n",r);
	
	return (0);
}

