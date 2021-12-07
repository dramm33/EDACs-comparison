#include <hf-risc.h>

#define BYTE_TO_BINARY_PATTERN "|%c%c%c%c%c%c%c%c|"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

#define ELEMENTS     20
#define SEED         2056
#define ERRORS       1056
#define ADDR_START 0x40000f4c
#define ADDR_END 0x40001040
#define ADDR_OFFSET ((ADDR_END-ADDR_START)/4)
unsigned int v[ELEMENTS];
unsigned char parity_v[ELEMENTS];
unsigned char parity_instr[ADDR_OFFSET+1];
unsigned char stop = 0;
static const unsigned int VECTOR[] = {
    4249370897, 4120116738, 3893066085, 3554368545, 3411880273,
    3170317139, 2017225902, 1760215469, 1672188125, 1563555666,
    1395757337, 1253227066, 1142433761, 1027384801,  948896551,
     904568615,  672436002,  497962649,  352548160,  231613132};

void swap(unsigned int vector[],int k);
void task1(void);
void task2(void);
void edac_wash(void);
unsigned char encode(unsigned int* addr);
int decode(unsigned int* addr, unsigned char parity);
void saboteur(void);
int randomn(int n);

int main(void)
{
	void (*task_sched[])(void) = {task1, saboteur, edac_wash, task2};
	int i = 0;

	while (1) {
		(*task_sched[i++])();
		if (i == sizeof(task_sched) / sizeof(void *)) return 0;
	}
}

void task1(void)
{
    //vector declaration
	printf("Calculating EDAC codes\n");

    memcpy(v, VECTOR, sizeof(VECTOR));

	printf("Vector created:\n");
	for(int k=0; k<ELEMENTS; k++){
		printf("%u\n", v[k]);
        parity_v[k] = encode((unsigned int*)(v+k));
    }

    int *addr_start= (int *)ADDR_START;

    for(int k=0; k<=ADDR_OFFSET; k++){
        parity_instr[k] = encode((unsigned int*)addr_start+k);
    }
}

void task2(void)
{
    if(stop)return;
    //Bubblesort
	printf("Sorting\n");
	volatile unsigned int time;
	time = TIMER0;
    int j, k;

    for (j = 0; j < ELEMENTS; j++) {
        for (k = j - 1; k >= 0 && v[k] > v[k+1]; k--) {
            int temp;

            temp = v[k];
            v[k] = v[k+1];
            v[k+1] = temp;
        }
    }
	time = TIMER0 - time;

    int i;
	printf("%d cycles", time);
	printf("\n\nsorted elements:\n", time);
	for(i=0; i<ELEMENTS; i++)
		printf("%u\n", v[i]);
    printf("DONE\n");
}

void edac_wash(void)
{
    int error = 0;
	printf("\n\nWashing data\n");
	for(int k=0; k<ELEMENTS; k++){
        error = decode((unsigned int*)(v+k), parity_v[k]);
        if (error==1){
            parity_v[k] = encode((unsigned int*)(v+k));
        } else if (error==2){
            printf("DOUBLE error detected\n");
            stop=1;
            return;
        }
    }
	printf("\n\nWashing instr\n");
    unsigned int *addr_start= (unsigned int *)ADDR_START;
    for(int k=0; k<=ADDR_OFFSET; k++){
        error=0;
        error = decode((unsigned int*)addr_start+k,  parity_instr[k]);
        if (error==1){
            parity_instr[k] = encode((unsigned int*)addr_start+k);
        } else if (error==2){
            printf("DOUBLE error detected\n");
            stop=1;
            return;
        }
    }

}

unsigned char encode(unsigned int* addr){
    unsigned int data = *addr;
    unsigned char temp = 0;
    unsigned char parity = 0;
    //calculate parity
    //p1
    temp = 0;
    temp ^= (1 & parity) ^ (1 & data);
    temp ^= (1 & (data>>1)) ^ (1 & (data>>3));
    for(int kbit=4;kbit<9;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+2)));
    }
    for(int kbit=11;kbit<24;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+2)));
    }
    temp ^= (1 & (data>>26)) ^ (1 & (data>>28)) ^ (1 & (data>>30));
    parity |= (temp & 1)<<0;
    //p2
    temp = 0;
    temp ^= (1 & (parity>>1)) ^ (1 & data);
    temp ^= (1 & (data>>2)) ^ (1 & (data>>3));
    for(int kbit=5;kbit<11;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    for(int kbit=12;kbit<25;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    temp ^= (1 & (data>>27)) ^ (1 & (data>>28)) ^ (1 & (data>>31));
    parity |= (temp & 1)<<1;
    //p4
    temp = 0;
    temp ^= (1 & (parity>>2)) ^ (1 & (data>>1)) ^ (1 & (data>>2)) ^ (1 & (data>>3));
    temp ^= (1 & (data>>7)) ^ (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10));
    for(int kbit=14;kbit<23;kbit+=8){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1))) ^ (1 & (data>>(kbit+2))) ^ (1 & (data>>(kbit+3)));
    }
    temp ^= (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity |= (temp & 1)<<2;
    //p8
    temp = 0;
    temp ^= (1 & (parity>>3)) ^ (1 & (data>>4)) ^ (1 & (data>>5)) ^ (1 & (data>>6)) ^ (1 & (data>>7)) ^ (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10));
    temp ^= (1 & (data>>18)) ^ (1 & (data>>19)) ^ (1 & (data>>20)) ^ (1 & (data>>21)) ^ (1 & (data>>22)) ^ (1 & (data>>23)) ^ (1 & (data>>24)) ^ (1 & (data>>25));
    parity |= (temp & 1)<<3;
    //p16
    temp = 0;
    temp ^= (1 & parity>>4) ^ (1 & data>>11);
    for(int kbit=12;kbit<25;kbit+=2){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    parity |= (temp & 1)<<4;
    //p32
    temp = 0;
    temp ^= (1 & (parity>>5)) ^ (1 & (data>>26)) ^ (1 & (data>>27)) ^ (1 & (data>>28)) ^ (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity |= (temp & 1)<<5;
    //P
    temp = 0;
    temp ^= (1 & parity) ^ (1 & (parity>>1)) ^ (1 & (parity>>2)) ^ (1 & (parity>>3)) ^ (1 & (parity>>4)) ^ (1 & (parity>>5));
    for(int kbit=0;kbit<31;kbit+=2){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    parity |= (temp & 1)<<6;


    return parity;
}
int decode(unsigned int* addr, unsigned char parity){
    int error = 0;
    unsigned int data = *addr;

    //check parity
    //p1
    int temp = 0;
    temp ^= (1 & parity) ^ (1 & data);
    temp ^= (1 & (data>>1)) ^ (1 & (data>>3));
    for(int kbit=4;kbit<9;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+2)));
    }
    for(int kbit=11;kbit<24;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+2)));
    }
    temp ^= (1 & (data>>26)) ^ (1 & (data>>28)) ^ (1 & (data>>30));
    int parity_new = 0;
    parity_new |= (temp & 1)<<0;
    //p2
    temp = 0;
    temp ^= (1 & (parity>>1)) ^ (1 & data);
    temp ^= (1 & (data>>2)) ^ (1 & (data>>3));
    for(int kbit=5;kbit<11;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    for(int kbit=12;kbit<25;kbit+=4){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    temp ^= (1 & (data>>27)) ^ (1 & (data>>28)) ^ (1 & (data>>31));
    parity_new |= (temp & 1)<<1;
    //p4
    temp = 0;
    temp ^= (1 & (parity>>2)) ^ (1 & (data>>1)) ^ (1 & (data>>2)) ^ (1 & (data>>3));
    temp ^= (1 & (data>>7)) ^ (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10));
    for(int kbit=14;kbit<23;kbit+=8){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1))) ^ (1 & (data>>(kbit+2))) ^ (1 & (data>>(kbit+3)));
    }
    temp ^= (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity_new |= (temp & 1)<<2;
    //p8
    temp = 0;
    temp ^= (1 & (parity>>3)) ^ (1 & (data>>4)) ^ (1 & (data>>5)) ^ (1 & (data>>6)) ^ (1 & (data>>7)) ^ (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10));
    temp ^= (1 & (data>>18)) ^ (1 & (data>>19)) ^ (1 & (data>>20)) ^ (1 & (data>>21)) ^ (1 & (data>>22)) ^ (1 & (data>>23)) ^ (1 & (data>>24)) ^ (1 & (data>>25));
    parity_new |= (temp & 1)<<3;
    //p16
    temp = 0;
    temp ^= (1 & parity>>4) ^ (1 & data>>11);
    for(int kbit=12;kbit<25;kbit+=2){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }
    parity_new |= (temp & 1)<<4;
    //p32
    temp = 0;
    temp ^= (1 & (parity>>5)) ^ (1 & (data>>26)) ^ (1 & (data>>27)) ^ (1 & (data>>28)) ^ (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity_new |= (temp & 1)<<5;
    //P
    temp = 0;
    temp ^= (1 & parity) ^ (1 & (parity>>1)) ^ (1 & (parity>>2)) ^ (1 & (parity>>3)) ^ (1 & (parity>>4)) ^ (1 & (parity>>5)) ^ (1 & (parity>>6));
    for(int kbit=0;kbit<31;kbit+=2){
        temp ^= (1 & (data>>kbit)) ^ (1 & (data>>(kbit+1)));
    }


    if(parity_new){

        printf("addr = 0x%08X\n", addr);
        printf("Data:               ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        printf("Par = ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
        printf("\n");
        printf("P = %d\n", temp);
        printf("ParN= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
        printf("\n");

        if(temp){
            if(parity_new-1>0){
                error = 1;
                //toggle bit
                if(parity_new-1<2){
                    parity ^= (1 << (parity_new-1));
                } else if(parity_new-1<3){
                    data ^= (1 << (parity_new-(1+2)));
                } else if(parity_new-1<4){
                    parity ^= (1 << (parity_new-(1+1)));
                } else if(parity_new-1<7){
                    data ^= (1 << (parity_new-(1+3)));
                } else if(parity_new-1<8){
                    parity ^= (1 << (parity_new-(1+4)));
                } else if(parity_new-1<15){
                    data ^= (1 << (parity_new-(1+4)));
                } else if(parity_new-1<16){
                    parity ^= (1 << (parity_new-(1+11)));
                } else if(parity_new-1<31){
                    data ^= (1 << (parity_new-(1+5)));
                } else if(parity_new-1<32){
                    parity ^= (1 << (parity_new-(1+26)));
                } else if(parity_new-1<38){
                    data ^= (1 << (parity_new-(1+6)));
                } else if(parity_new-1<39){
                    parity ^= (1 << (parity_new-(1+32)));
                }
            }
        printf("Data_Corrected:     ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        *addr = data;
        } else {
            error = 2;
        }
    }

    // add P to parity byte
    parity |= (temp & 1)<<6;

    return error;
}
void saboteur(void)
{
	printf("\n\nSabotaging\n");
    srand(SEED);
    for(int k=0;k<ERRORS;k++){
        int boolean = 0;
        boolean = randomn(1);
        if (boolean){
            int addr=0;
            addr = randomn(ADDR_OFFSET-1);
            int *addr_start= (int *)ADDR_START;

            printf("addr = 0x%08X\n", addr+addr_start);
            printf("value = 0x%08X\n", *(addr_start+addr));

            int bit=0;
            bit = randomn(38);
            printf("instr_bit = %d\n", bit);
            if(bit<2){
                parity_instr[addr] ^= (1 << (bit));
            } else if(bit<3){
                *(addr_start+addr) ^= (1 << (bit-2));
            } else if(bit<4){
                parity_instr[addr] ^= (1 << (bit-1));
            } else if(bit<7){
                *(addr_start+addr) ^= (1 << (bit-3));
            } else if(bit<8){
                parity_instr[addr] ^= (1 << (bit-4));
            } else if(bit<15){
                *(addr_start+addr) ^= (1 << (bit-4));
            } else if(bit<16){
                parity_instr[addr] ^= (1 << (bit-11));
            } else if(bit<31){
                *(addr_start+addr) ^= (1 << (bit-5));
            } else if(bit<32){
                parity_instr[addr] ^= (1 << (bit-26));
            } else if(bit<38){
                *(addr_start+addr) ^= (1 << (bit-6));
            } else if(bit<39){
                parity_instr[addr] ^= (1 << (bit-32));
            }
        } else {
            int v_pos = randomn(ELEMENTS);
            int bit=0;
            bit = randomn(38);
            printf("addr = 0x%08X\n", &v[v_pos]);
            printf("value = %u\n", v[v_pos]);
            printf("v_bit = %d\n", bit);

            if(bit<2){
                parity_v[v_pos] ^= (1 << (bit));
            } else if(bit<3){
                v[v_pos] ^= (1 << (bit-2));
            } else if(bit<4){
                parity_v[v_pos] ^= (1 << (bit-1));
            } else if(bit<7){
                v[v_pos] ^= (1 << (bit-3));
            } else if(bit<8){
                parity_v[v_pos] ^= (1 << (bit-4));
            } else if(bit<15){
                v[v_pos] ^= (1 << (bit-4));
            } else if(bit<16){
                parity_v[v_pos] ^= (1 << (bit-11));
            } else if(bit<31){
                v[v_pos] ^= (1 << (bit-5));
            } else if(bit<32){
                parity_v[v_pos] ^= (1 << (bit-26));
            } else if(bit<38){
                v[v_pos] ^= (1 << (bit-6));
            } else if(bit<39){
                parity_v[v_pos] ^= (1 << (bit-32));
            }
        }
    }
}

int randomn(int n){
    int r=0;
    int max = 32767/(n+1)*(n+1);
    while((r = random()) >= max);
    r = r % (n+1);
    return r;
}
