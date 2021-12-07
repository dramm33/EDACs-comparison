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
#define SEED         3010
#define ERRORS       10
#define ADDR_START  0x40001164
#define ADDR_END 0x40001258
#define ADDR_OFFSET ((ADDR_END-ADDR_START)/4)
unsigned int v[ELEMENTS];
unsigned int v_d[ELEMENTS];
unsigned char parity_v[ELEMENTS];
unsigned char parity_instr[ADDR_OFFSET+1];
unsigned int instr_d[ADDR_OFFSET+1];
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
unsigned char encode(unsigned int* addr, unsigned int* addr_d);
int decode(unsigned int* addr, unsigned int* addr_d, unsigned char parity);
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
        parity_v[k] = encode((unsigned int*)(v+k),(unsigned int*)(v_d+k));
    }

    int *addr_start= (int *)ADDR_START;

    for(int k=0; k<=ADDR_OFFSET; k++){
        parity_instr[k] = encode((unsigned int*)addr_start+k, instr_d+k);
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
        error = decode((unsigned int*)(v+k), (unsigned int*)(v_d+k), parity_v[k]);
        if (error==1){
            parity_v[k] = encode((unsigned int*)(v+k), (unsigned int*)(v_d+k));
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
        error = decode((unsigned int*)addr_start+k, instr_d+k, parity_instr[k]);
        if (error==1){
            parity_instr[k] = encode((unsigned int*)addr_start+k, instr_d+k);
        } else if (error==2){
            printf("DOUBLE error detected\n");
            stop=1;
            return;
        }
    }

}

unsigned char encode(unsigned int* addr, unsigned int* addr_d){
    unsigned int data = *addr;

    unsigned char temp = 0;
    unsigned char parity = 0;

    //calculate parity
    //byte 1
    temp = 0;
    temp ^= (1 & data) ^ (1 & (data>>1)) ^ (1 & (data>>2)) ^ (1 & (data>>3));
    temp ^= (1 & (data>>4)) ^ (1 & (data>>5)) ^ (1 & (data>>6)) ^ (1 & (data>>7));
    parity |= (temp & 1)<<0;
    parity |= (temp & 1)<<4;

    //byte 2
    temp = 0;
    temp ^= (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10)) ^ (1 & (data>>11));
    temp ^= (1 & (data>>12)) ^ (1 & (data>>13)) ^ (1 & (data>>14)) ^ (1 & (data>>15));
    parity |= (temp & 1)<<1;
    parity |= (temp & 1)<<5;

    //byte 3
    temp = 0;
    temp ^= (1 & (data>>16)) ^ (1 & (data>>17)) ^ (1 & (data>>18)) ^ (1 & (data>>19));
    temp ^= (1 & (data>>20)) ^ (1 & (data>>21)) ^ (1 & (data>>22)) ^ (1 & (data>>23));
    parity |= (temp & 1)<<2;
    parity |= (temp & 1)<<6;

    //byte 4
    temp = 0;
    temp ^= (1 & (data>>24)) ^ (1 & (data>>25)) ^ (1 & (data>>26)) ^ (1 & (data>>27));
    temp ^= (1 & (data>>28)) ^ (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity |= (temp & 1)<<3;
    parity |= (temp & 1)<<7;

    //duplicate data
    *addr_d = data;

    return parity;
}
int decode(unsigned int* addr, unsigned int*addr_d, unsigned char parity){
    int error = 0;
    unsigned char temp = 0;
    unsigned char parity_new = 0;
    unsigned int data = *addr;
    unsigned int data_d = *addr_d;

    //check parity
    //byte 1
    temp = 0;
    temp ^= (1 & data) ^ (1 & (data>>1)) ^ (1 & (data>>2)) ^ (1 & (data>>3));
    temp ^= (1 & (data>>4)) ^ (1 & (data>>5)) ^ (1 & (data>>6)) ^ (1 & (data>>7));
    parity_new |= (temp & 1)<<0;

    //byte 2
    temp = 0;
    temp ^= (1 & (data>>8)) ^ (1 & (data>>9)) ^ (1 & (data>>10)) ^ (1 & (data>>11));
    temp ^= (1 & (data>>12)) ^ (1 & (data>>13)) ^ (1 & (data>>14)) ^ (1 & (data>>15));
    parity_new |= (temp & 1)<<1;

    //byte 3
    temp = 0;
    temp ^= (1 & (data>>16)) ^ (1 & (data>>17)) ^ (1 & (data>>18)) ^ (1 & (data>>19));
    temp ^= (1 & (data>>20)) ^ (1 & (data>>21)) ^ (1 & (data>>22)) ^ (1 & (data>>23));
    parity_new |= (temp & 1)<<2;

    //byte 4
    temp = 0;
    temp ^= (1 & (data>>24)) ^ (1 & (data>>25)) ^ (1 & (data>>26)) ^ (1 & (data>>27));
    temp ^= (1 & (data>>28)) ^ (1 & (data>>29)) ^ (1 & (data>>30)) ^ (1 & (data>>31));
    parity_new |= (temp & 1)<<3;

    //byte_d 1
    temp = 0;
    temp ^= (1 & data_d) ^ (1 & (data_d>>1)) ^ (1 & (data_d>>2)) ^ (1 & (data_d>>3));
    temp ^= (1 & (data_d>>4)) ^ (1 & (data_d>>5)) ^ (1 & (data_d>>6)) ^ (1 & (data_d>>7));
    parity_new |= (temp & 1)<<4;

    //byte_d 2
    temp = 0;
    temp ^= (1 & (data_d>>8)) ^ (1 & (data_d>>9)) ^ (1 & (data_d>>10)) ^ (1 & (data_d>>11));
    temp ^= (1 & (data_d>>12)) ^ (1 & (data_d>>13)) ^ (1 & (data_d>>14)) ^ (1 & (data_d>>15));
    parity_new |= (temp & 1)<<5;

    //byte_d 3
    temp = 0;
    temp ^= (1 & (data_d>>16)) ^ (1 & (data_d>>17)) ^ (1 & (data_d>>18)) ^ (1 & (data_d>>19));
    temp ^= (1 & (data_d>>20)) ^ (1 & (data_d>>21)) ^ (1 & (data_d>>22)) ^ (1 & (data_d>>23));
    parity_new |= (temp & 1)<<6;

    //byte_d 4
    temp = 0;
    temp ^= (1 & (data_d>>24)) ^ (1 & (data_d>>25)) ^ (1 & (data_d>>26)) ^ (1 & (data_d>>27));
    temp ^= (1 & (data_d>>28)) ^ (1 & (data_d>>29)) ^ (1 & (data_d>>30)) ^ (1 & (data_d>>31));
    parity_new |= (temp & 1)<<7;

    uint8_t bneq_pok = 0; //4bits for p_pk and 4bits for b_neq

    bneq_pok |= !( (data & 0xFF) == (data_d & 0xFF) )<<0;
    bneq_pok |= !( ((data>>8) & 0xFF) == ((data_d>>8) & 0xFF) )<<1;
    bneq_pok |= !( ((data>>16) & 0xFF) == ((data_d>>16) & 0xFF) )<<2;
    bneq_pok |= !( ((data>>24) & 0xFF) == ((data_d>>24) & 0xFF) )<<3;

    bneq_pok |= !(((parity_new & 1) ^ (parity & 1)) || (((parity_new>>4) & 1) ^ ((parity>>4) &1)))<<4;
    bneq_pok |= !((((parity_new>>1) & 1) ^ ((parity>>1) & 1)) || (((parity_new>>5) & 1) ^ ((parity>>5) &1)))<<5;
    bneq_pok |= !((((parity_new>>2) & 1) ^ ((parity>>2) & 1)) || (((parity_new>>6) & 1) ^ ((parity>>6) &1)))<<6;
    bneq_pok |= !((((parity_new>>3) & 1) ^ ((parity>>3) & 1)) || (((parity_new>>7) & 1) ^ ((parity>>7) &1)))<<7;


    if( (
        (((parity_new & 1) ^ (parity & 1)) && (((parity_new>>4) & 1) ^ ((parity>>4) &1))) ||
        ((((parity_new>>1) & 1) ^ ((parity>>1) & 1)) && (((parity_new>>5) & 1) ^ ((parity>>5) &1))) ||
        ((((parity_new>>2) & 1) ^ ((parity>>2) & 1)) && (((parity_new>>6) & 1) ^ ((parity>>6) &1))) ||
        ((((parity_new>>3) & 1) ^ ((parity>>3) & 1)) && (((parity_new>>7) & 1) ^ ((parity>>7) &1)))
        ) || (
        ((bneq_pok & 1) && ((bneq_pok>>4) & 1)) || (((bneq_pok>>1) & 1) && ((bneq_pok>>5) & 1)) ||
        (((bneq_pok>>2) & 1) && ((bneq_pok>>6) & 1)) || (((bneq_pok>>3) & 1) && ((bneq_pok>>7) & 1))
        )
      ){
        //detected
        //printf("detected\n");
        error = 2;
        printf("addr = 0x%08X\n", addr);
        printf("Data:               ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        printf("Data_d:             ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data_d>>24), BYTE_TO_BINARY(data_d>>16), BYTE_TO_BINARY(data_d>>8), BYTE_TO_BINARY(data_d));
        printf("\n");
        printf("Par= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
        printf("\n");
        printf("bneq_pok= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(bneq_pok));
        printf("\n");
        printf("ParN=");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
        printf("\n");
    } else if( (
        (((((parity_new & 1) ^ (parity & 1)) != (((parity_new>>4) & 1) ^ ((parity>>4) &1))) ||
        ((((parity_new>>1) & 1) ^ ((parity>>1) & 1)) != (((parity_new>>5) & 1) ^ ((parity>>5) &1)))) ||
        ((((parity_new>>2) & 1) ^ ((parity>>2) & 1)) != (((parity_new>>6) & 1) ^ ((parity>>6) &1)))) ||
        ((((parity_new>>3) & 1) ^ ((parity>>3) & 1)) != (((parity_new>>7) & 1) ^ ((parity>>7) &1)))
        ) && (
        !(((bneq_pok & 1) && ((bneq_pok>>4) & 1)) || (((bneq_pok>>1) & 1) && ((bneq_pok>>5) & 1)) ||
        (((bneq_pok>>2) & 1) && ((bneq_pok>>6) & 1)) || (((bneq_pok>>3) & 1) && ((bneq_pok>>7) & 1)))
        )
            ){
        //corrected
        printf("addr = 0x%08X\n", addr);
        printf("Data:               ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        printf("Data_d:             ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data_d>>24), BYTE_TO_BINARY(data_d>>16), BYTE_TO_BINARY(data_d>>8), BYTE_TO_BINARY(data_d));
        printf("\n");
        printf("Par= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
        printf("\n");
        printf("bneq_pok= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(bneq_pok));
        printf("\n");
        printf("ParN=");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
        printf("\n");
        error = 1;
        if ( (parity_new & 1) ^ (parity & 1) ){
            //use data_d
            data = (data & ~(0xFF<<0)) | (data_d&(0xFF<<0));
        }
        if ( ((parity_new>>1) & 1) ^ ((parity>>1) & 1) ){
            //use data_d
            data = (data & ~(0xFF00)) | (data_d&(0xFF00));
        }
        if ( ((parity_new>>2) & 1) ^ ((parity>>2) & 1) ){
            //use data_d
            data = (data & ~(0xFF0000)) | (data_d&(0xFF0000));
        }
        if ( ((parity_new>>3) & 1) ^ ((parity>>3) & 1) ){
            //use data_d
            data = (data & ~(0xFF000000)) | (data_d&(0xFF000000));
        }
        printf("Data_Corrected:     ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        *addr=data;
        *addr_d=data_d;
    }
    //printf("error = %d\n", error);


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
            bit = randomn(71);
            printf("instr_bit = %d\n", bit);
            if(bit<1){
                parity_instr[addr] ^= (1 << (bit));
            } else if(bit<9){
                *(addr_start+addr) ^= (1 << (bit-1));
            } else if(bit<10){
                parity_instr[addr] ^= (1 << (bit-8));
            } else if(bit<18){
                *(addr_start+addr) ^= (1 << (bit-2));
            } else if(bit<19){
                parity_instr[addr] ^= (1 << (bit-16));
            } else if(bit<27){
                *(addr_start+addr) ^= (1 << (bit-3));
            } else if(bit<28){
                parity_instr[addr] ^= (1 << (bit-24));
            } else if(bit<36){
                *(addr_start+addr) ^= (1 << (bit-4));
            } else if(bit<37){
                parity_instr[addr] ^= (1 << (bit-32)); //32
            } else if(bit<45){
                instr_d[addr] ^= (1 << (bit-37)); //36+1
            } else if(bit<46){
                parity_instr[addr] ^= (1 << (bit-40));//32+8
            } else if(bit<54){
                instr_d[addr] ^= (1 << (bit-38)); //36+2
            } else if(bit<55){
                parity_instr[addr] ^= (1 << (bit-48));//32+16
            } else if(bit<63){
                instr_d[addr] ^= (1 << (bit-39)); //36+3
            } else if(bit<64){
                parity_instr[addr] ^= (1 << (bit-56));//32+24
            } else if(bit<72){
                instr_d[addr] ^= (1 << (bit-40)); //36+4
            }
        } else {
            int v_pos = randomn(ELEMENTS);
            int bit=0;
            bit = randomn(71);
            printf("addr = 0x%08X\n", &v[v_pos]);
            printf("value = %u\n", v[v_pos]);
            printf("v_bit = %d\n", bit);

            if(bit<1){
                parity_v[v_pos] ^= (1 << (bit));
            } else if(bit<9){
                v[v_pos] ^= (1 << (bit-1));
            } else if(bit<10){
                parity_v[v_pos] ^= (1 << (bit-8));
            } else if(bit<18){
                v[v_pos] ^= (1 << (bit-2));
            } else if(bit<19){
                parity_v[v_pos] ^= (1 << (bit-16));
            } else if(bit<27){
                v[v_pos] ^= (1 << (bit-3));
            } else if(bit<28){
                parity_v[v_pos] ^= (1 << (bit-24));
            } else if(bit<36){
                v[v_pos] ^= (1 << (bit-4));
            } else if(bit<37){
                parity_v[v_pos] ^= (1 << (bit-32)); //32
            } else if(bit<45){
                v_d[v_pos] ^= (1 << (bit-37)); //36+1
            } else if(bit<46){
                parity_v[v_pos] ^= (1 << (bit-40));//32+8
            } else if(bit<54){
                v_d[v_pos] ^= (1 << (bit-38)); //36+2
            } else if(bit<55){
                parity_v[v_pos] ^= (1 << (bit-48));//32+16
            } else if(bit<63){
                v_d[v_pos] ^= (1 << (bit-39)); //36+3
            } else if(bit<64){
                parity_v[v_pos] ^= (1 << (bit-56));//32+24
            } else if(bit<72){
                v_d[v_pos] ^= (1 << (bit-40)); //36+4
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
