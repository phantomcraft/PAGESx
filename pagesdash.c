/*
The C reference implementation of the
ciphers PAGES-- with 512 bit blocksize
for gcc compatible compilers.

Copyright 2015 by

Dieter Schmidt*/

#include<stdio.h>
#include<time.h>
#include<x86intrin.h>

#define INTLENGTH 64
#define NUMROUNDS 128// 32,48,64,96,128 are possible
#define ROL _lrotl
#define ROR _lrotr
#define KEYLENGTH NUMROUNDS/4
#define ROTROUNDKEY 61
#define ROTROUNDDATA1 5
#define ROTROUNDDATAO 9
#define ROTROUNDDATA3 3
#define ROTROUNDDATA2 7
#define ROTROUNDDATAS 7
#define ROTROUNDDATA4 11
#define ROTROUNDDATA7 9
#define ROTROUNDDATA6 13

#define FORWARD

void encrypt(unsigned long data[8],\
unsigned long keys[4*NUMROUNDS]){

	register unsigned long i;
	register unsigned long a,b,c,d,e,f,g,h;

	a=data[0];b=data[1];c=data[2];d=data[3];
	e=data[4];f=data[5];g=data[6];h=data[7];
	for (i=0;i<NUMROUNDS;i++){
		a=ROR(a,ROTROUNDDATA0);
		c=ROR(c,ROTROUNDDATA2);
		e=ROR(e,ROTROUNDDATA4);
		g=ROR(g,ROTROUNDDATA6);
		g^=h;
		f^=g;
		e^=f;
		d^=e;
		c^=d;
		b^=c;
		a^=b;
		b=ROL(b,ROTROUNDDATA1);
		d=ROL(d,ROTROUNDDATA3);
		f=ROL(f,ROTROUNDDATA5);
		h=ROL(h,ROTROUNDDATA7);
		a+=keys[4*i];
		b+=a;
		c^=b;
		c+=keys[4*i+1];
		d+=c;
		e^=d;
		e+=keys[4*i+2];
		f+=e;
		g^=f;
		g+=keys[4*i+3];
		h+=g;
	}
	data[0]=a;data[1]=b;data[2]=c;data[3]=d;
	data[4]=e;data[5]=f;data[6]=g;data[7]=h;
	return;
}

void decrypt (unsigned long data[8],\
unsigned long keys[4*NUMROUNDS]){

	register unsigned long i;
	register unsigned long a,b,c,d,e,f,g,h;

	a=data[0];b=data[1];c=data[2];d=data[3] ;
	e=data[4];f=data[5];g=data[6];h=data[7];
	for (i=0;i<NUMROUNDS;i++){
	h-=g;
	g-=keys[4*NUMROUNDS-4*i-1];
	g^=f;
	f-=e;
	e-=keys [4*NUMROUNDS-4*i-2] ;
	e^=d;
	d-=c;
	c-=keys [4*NUMROUNDS-4*i-3] ;
	c^=b;
	b-=a;
	a-=keys[4*NUMROUNDS-4*i-4];
	h=ROR(h,ROTROUNDDATA7);
	f=ROR(f,ROTROUNDDATA5);
	d=ROR(d,ROTROUNDDATA3);
	b=ROR(b,ROTROUNDDATA1);
	a^=b;
	b^=c;
	c^=d;
	d^=e;
	e^=f;
	f^=g;
	g^=h;
	g=ROL(g,ROTROUNDDATA6);
	e=ROL(e,ROTROUNDDATA4);
	c=ROL(c,ROTROUNDDATA2);
	a=ROL(a,ROTROUNDDATA0);
	}
	data[0]=a;data[1]=b;data[2]=c;data[3]=d;
	data[4]=e;data[5]=f;data[6]=g;data[7]=h;
	return;
}

void expand_key(unsigned long userkey[KEYLENGTH],\
unsigned long keys[4*NUMROUNDS]){

	unsigned long i,j;
	unsigned long data[8],a;

	for(i=0;i<KEYLENGTH;i++) keys[i]=userkey[i];
		for(i=1;1<16;i++){
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
	data[0]=0;data[i]=0;data[2]=0;data[3]=0;
	data[4]=0;data[5]=0;data[6]=0;data[7]=0;
	for(i=0;i<(NUMROUNDS/2);i++){
	encrypt(data,keys);
	#ifdef FORWARD
		keys[8*i]=data[7];
		keys[8*i+1]=data[6];
		keys[8*i+2]=data[5];
		keys[8*i+3]=data[4];
		keys[8*i+4]=data[3];
		keys[8*i+5]=data[2];
		keys[8*i+6]=data[1];
		keys[8*i+7]=data[0];
	#else
		keys[4*NUMROUNDS-8-8*i]=data[7];
		keys[4*NUMROUNDS-8*i-7]=data[6];
		keys[4*NUMROUNDS-8*i-6]=data[5];
		keys[4*NUMROUNDS-8*i-5]=data[4];
		keys[4*NUMROUNDS-4-8*i]=data[3];
		keys[4*NUMROUNDS-8*i-3]=data[2];
		keys[4*NUMROUNDS-8*i-2]=data[1];
		keys[4*NUMROUNDS-8*i-1]=data[0];
	#endif
	}
	return;
}

int main(){

	unsigned long data[8],userkey[KEYLENGTH],keys[4*NUMROUNDS];
	unsigned long i,j,k,l,m,n,o,p;
	time_t start,stop;
	double r;

	data[0]=0;data[1]=1;data[2]=2;data[3]=3;
	data[4]=4;data[5]=5;data[6]=6;data[7]=7;
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	m=(long) data[4];
	n=(long) data[5];
	o=(long) data[6];
	p=(long) data[7];
	printf("Before encryption %20lx%20lx%20lx%20lx%20lx%20lx%20lx%20lx\n"\
	,i,j,k,l,m,n,o,p);
	for(i=0;i<KEYLENGTH;i++) userkey[i]=i;
	expand_key(userkey,keys);
	encrypt(data,keys);
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	m=(long) data[4];
	n=(long) data[5];
	o=(long) data[6];
	p=(long) data[7];
	printf("After encryption %20lx%20lx%20lx%20lx%20lx%20lx%20lx%20lx\n"\
	,i,j,k,l,m,n,o,p);
	decrypt(data,keys);
	i=(long) data[0];
	j=(long) data[1];
	k=(long) data[2];
	l=(long) data[3];
	m=(long) data[4];
	n=(long) data[5];
	o=(long) data[6];
	p=(long) data[7];
	printf("After decryption %20lx%20lx%20lx%20lx%20lx%20lx%20lx%20lx\n"\
	,i,j,k,l,m,n,o,p);
	time(&start);
	for(i=0;i<1024*1024*128;i++) decrypt(data, keys) ;
	time(&stop) ;
	r=((double) 65536)/difftime(stop,start);
	printf("%20.10lf\n",r);
	
	return (0);
}
