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
#define SEED         5100
#define ERRORS       100
#define ADDR_START  0x40000d80
#define ADDR_END 0x40000e74
#define ADDR_OFFSET ((ADDR_END-ADDR_START)/4)
unsigned int v[ELEMENTS];
unsigned int v_p[ELEMENTS];
unsigned char parity_v[ELEMENTS];
unsigned char parity_instr[ADDR_OFFSET+1];
unsigned int instr_p[ADDR_OFFSET+1];
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
unsigned char encode(unsigned int* addr, unsigned int* addr_p);
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
        parity_v[k] = encode((unsigned int*)(v+k),(unsigned int*)(v_p+k));
    }

    int *addr_start= (int *)ADDR_START;

    for(int k=0; k<=ADDR_OFFSET; k++){
        parity_instr[k] = encode((unsigned int*)addr_start+k, instr_p+k);
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
        error = decode((unsigned int*)(v+k), (unsigned int*)(v_p+k), parity_v[k]);
        if (error==1){
            parity_v[k] = encode((unsigned int*)(v+k), (unsigned int*)(v_p+k));
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
        error = decode((unsigned int*)addr_start+k, instr_p+k, parity_instr[k]);
        if (error==1){
            parity_instr[k] = encode((unsigned int*)addr_start+k, instr_p+k);
        } else if (error==2){
            printf("DOUBLE error detected\n");
            stop=1;
            return;
        }
    }

}

unsigned char encode(unsigned int* addr, unsigned int* addr_p){
    unsigned int data = *addr;
    unsigned int data_p = *addr_p;

    unsigned char temp = 0;
    unsigned char parity = 0;

    //calculate parity for each byte row
    for(int k=0;k<4;k++){
        //CBp1
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+0))) ^ (1 & (data>>(k*8)));
        temp ^= (1 & (data>>(k*8+1))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+4))) ^ (1 & (data>>(k*8+6)));
        data_p |= (temp & 1)<<(k*5+0);
        //CBp2
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+1))) ^ (1 & (data>>(k*8)));
        temp ^= (1 & (data>>(k*8+2))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+5))) ^ (1 & (data>>(k*8+6)));
        data_p |= (temp & 1)<<(k*5+1);
        //CBp4
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+2))) ^ (1 & (data>>(k*8+1))) ^ (1 & (data>>(k*8+2))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+7)));
        data_p |= (temp & 1)<<(k*5+2);
        //CBp8
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+3))) ^ (1 & (data>>(k*8+4))) ^ (1 & (data>>(k*8+5))) ^ (1 & (data>>(k*8+6))) ^ (1 & (data>>(k*8+7)));
        data_p |= (temp & 1)<<(k*5+3);
        //Pa
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+0))) ^ (1 & (data_p>>(k*5+1))) ^ (1 & (data_p>>(k*5+2))) ^ (1 & (data_p>>(k*5+3)));
        for(int kbit=0;kbit<7;kbit+=2){
            temp ^= (1 & (data>>(k*8+kbit))) ^ (1 & (data>>(k*8+(kbit+1))));
        }
        data_p |= (temp & 1)<<(k*5+4);
    }
    //calculate parity for each column
    for(int k=0;k<8;k++){
        //P1
        temp = 0;
        temp ^= (1 & (data>>(k+0))) ^ (1 & (data>>(k+8))) ^ (1 & (data>>(k+16))) ^ (1 & (data>>(k+24)));
        data_p |= (temp & 1)<<(k+20);
    }
    for(int k=0;k<4;k++){
        temp = 0;
        temp ^= (1 & (data_p>>(k+0))) ^ (1 & (data_p>>(k+5))) ^ (1 & (data_p>>(k+10))) ^ (1 & (data_p>>(k+15)));
        data_p |= (temp & 1)<<(k+28);
    }
    temp = 0;
    temp ^= (1 & (data_p>>(4+0))) ^ (1 & (data_p>>(4+5))) ^ (1 & (data_p>>(4+10))) ^ (1 & (data_p>>(4+15)));
    parity |= (temp & 1)<<(0);


    *addr_p = data_p;


    return parity;
}
int decode(unsigned int* addr, unsigned int*addr_p, unsigned char parity){
    int error = 0;
    unsigned char scbspasp = 0;
    unsigned char scb_rows = 0;
    unsigned char temp = 0;
    unsigned char parity_new = 0;
    unsigned int data = *addr;
    unsigned int data_p = *addr_p;
    unsigned int data_p_r = 0;

    //check parity for each byte row
    for(int k=0;k<4;k++){
        //CBp1
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+0))) ^ (1 & (data>>(k*8)));
        temp ^= (1 & (data>>(k*8+1))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+4))) ^ (1 & (data>>(k*8+6)));
        data_p_r |= (temp & 1)<<(k*5+0);
        //CBp2
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+1))) ^ (1 & (data>>(k*8)));
        temp ^= (1 & (data>>(k*8+2))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+5))) ^ (1 & (data>>(k*8+6)));
        data_p_r |= (temp & 1)<<(k*5+1);
        //CBp4
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+2))) ^ (1 & (data>>(k*8+1))) ^ (1 & (data>>(k*8+2))) ^ (1 & (data>>(k*8+3)));
        temp ^= (1 & (data>>(k*8+7)));
        data_p_r |= (temp & 1)<<(k*5+2);
        //CBp8
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+3))) ^ (1 & (data>>(k*8+4))) ^ (1 & (data>>(k*8+5))) ^ (1 & (data>>(k*8+6))) ^ (1 & (data>>(k*8+7)));
        data_p_r |= (temp & 1)<<(k*5+3);
        //Pa
        temp = 0;
        temp ^= (1 & (data_p>>(k*5+0))) ^ (1 & (data_p>>(k*5+1))) ^ (1 & (data_p>>(k*5+2)));
        temp ^= (1 & (data_p>>(k*5+3))) ^ (1 & (data_p>>(k*5+4)));
        for(int kbit=0;kbit<7;kbit+=2){
            temp ^= (1 & (data>>(k*8+kbit))) ^ (1 & (data>>(k*8+(kbit+1))));
        }
        data_p_r |= (temp & 1)<<(k*5+4);
    }
    //calculate parity for each column
    for(int k=0;k<8;k++){
        temp = 0;
        temp ^= (1 & (data>>(k+0))) ^ (1 & (data>>(k+8))) ^ (1 & (data>>(k+16))) ^ (1 & (data>>(k+24)));
        temp ^= (1 & (data_p>>(k+20)));
        data_p_r |= (temp & 1)<<(k+20);
    }
    for(int k=0;k<4;k++){
        temp = 0;
        temp ^= (1 & (data_p>>(k+0))) ^ (1 & (data_p>>(k+5))) ^ (1 & (data_p>>(k+10))) ^ (1 & (data_p>>(k+15)));
        temp ^= (1 & (data_p>>(k+28)));
        data_p_r |= (temp & 1)<<(k+28);
    }
    temp = 0;
    temp ^= (1 & (data_p>>(4+0))) ^ (1 & (data_p>>(4+5))) ^ (1 & (data_p>>(4+10))) ^ (1 & (data_p>>(4+15)));
    temp ^= (1 & parity);
    parity_new |= (temp & 1)<<(0);

    //SCB
    temp = 0;
    temp |= (1& data_p_r>>(0)) | (1& data_p_r>>(1)) | (1& data_p_r>>(2)) | (1& data_p_r>>(3));
    temp |= (1& data_p_r>>(5)) | (1& data_p_r>>(6)) | (1& data_p_r>>(7)) | (1& data_p_r>>(8));
    temp |= (1& data_p_r>>(10)) | (1& data_p_r>>(11)) | (1& data_p_r>>(12)) | (1& data_p_r>>(13));
    temp |= (1& data_p_r>>(15)) | (1& data_p_r>>(16)) | (1& data_p_r>>(17)) | (1& data_p_r>>(18));
    scbspasp |= (temp & 1)<<2;
    //SPa
    temp = 0;
    temp |= (1& data_p_r>>(4)) | (1& data_p_r>>(9)) | (1& data_p_r>>(14)) | (1& data_p_r>>(19));
    scbspasp |= (temp & 1)<<1;
    //SP
    temp = 0;
    for(int kbit=0;kbit<11;kbit+=2){
        temp |= (1 & (data_p_r>>(20+kbit))) | (1 & (data_p_r>>(20+(kbit+1))));
    }
    temp |= (parity_new & 1);
    scbspasp |= (temp & 1)<<0;
    //count SCB rows
    scb_rows = 0;
    scb_rows += (1& data_p_r>>(0)) | (1& data_p_r>>(1)) | (1& data_p_r>>(2)) | (1& data_p_r>>(3));
    scb_rows += (1& data_p_r>>(5)) | (1& data_p_r>>(6)) | (1& data_p_r>>(7)) | (1& data_p_r>>(8));
    scb_rows += (1& data_p_r>>(10)) | (1& data_p_r>>(11)) | (1& data_p_r>>(12)) | (1& data_p_r>>(13));
    scb_rows += (1& data_p_r>>(15)) | (1& data_p_r>>(16)) | (1& data_p_r>>(17)) | (1& data_p_r>>(18));

    if( //((1 & scbspasp>>2)==0 && (1 & scbspasp>>1)==0 && (1 & scbspasp>>0)==1) ||
        ((1 & scbspasp>>2)==0 && (1 & scbspasp>>1)==1 && (1 & scbspasp>>0)==0) ||
        ((1 & scbspasp>>2)==1 && (1 & scbspasp>>1)==0 && (1 & scbspasp>>0)==0)
      ){
        //detected
        printf("detected\n");
        printf("addr = 0x%08X\n", addr);
        printf("Data:               ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        printf("Data_p_r:           ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data_p_r>>24), BYTE_TO_BINARY(data_p_r>>16), BYTE_TO_BINARY(data_p_r>>8), BYTE_TO_BINARY(data_p_r));
        printf("\n");
        printf("Par= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
        printf("\n");
        printf("ParN=");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
        printf("\n");
        printf("Syndrome= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(scbspasp));
        printf("\n");
        error = 2;
    } else if( ((1 & scbspasp>>2)==0 && (1 & scbspasp>>1)==1 && (1 & scbspasp>>0)==1) ||
               ((1 & scbspasp>>2)==1 && (1 & scbspasp>>1)==0 && (1 & scbspasp>>0)==1) ||
               ((1 & scbspasp>>2)==1 && (1 & scbspasp>>1)==1 && (1 & scbspasp>>0)==1 && scb_rows==1)
             ){
        //correct with SP
        printf("detected\n");
        printf("addr = 0x%08X\n", addr);
        printf("Data:               ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        printf("Data_p_r:           ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data_p_r>>24), BYTE_TO_BINARY(data_p_r>>16), BYTE_TO_BINARY(data_p_r>>8), BYTE_TO_BINARY(data_p_r));
        printf("\n");
        printf("Par= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
        printf("\n");
        printf("ParN=");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
        printf("\n");
        printf("Syndrome= ");
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(scbspasp));
        printf("\n");
        printf("scb_rows = %d\n",scb_rows);
        printf("using SP\n");
        error = 1;
        for(int k=0;k<4;k++){
            temp = 0;
            temp |= (1& data_p_r>>(0+5*k)) | (1& data_p_r>>(1+5*k)) | (1& data_p_r>>(2+5*k)) | (1& data_p_r>>(3+5*k));
            temp |= (1& data_p_r>>(4+5*k));
            if(temp){
                data = data ^ ( (data_p_r>>20) & 0xFF)<<(k*8);
                data_p = data_p ^ ( (data_p_r>>28) & 0xFF)<<(k*5);
                data_p = data_p ^ ( (parity_new) & 1)<<(k*5+4);
            }
        }

        printf("DataCorrected:      ");
        printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
        printf("\n");
        *addr = data;
        *addr_p = data_p;
    } else {
        //correct with hamming
        error = 1;
        for(int k=0;k<4;k++){
            if( (1 & data_p_r>>(k*5+4)) && ((data_p_r>>(k*5)) & 0xF) ){
                temp = 0;
                temp = ( (data_p_r>>(k*5)) & 0xF);
                printf("temp = %d\n", temp);
                if(temp-1<2){
                    data_p ^= (1 << ((temp-1)+k*5));
                } else if(temp-1<3){
                    data ^= (1 << ((temp-(1+2))+k*8));
                } else if(temp-1<4){
                    data_p ^= (1 << ((temp-(1+1))+k*5));
                } else if(temp-1<7){
                    data ^= (1 << ((temp-(1+3))+k*8));
                } else if(temp-1<8){
                    data_p ^= (1 << ((temp-(1+4))+k*5));
                } else if(temp-1<12){
                    data ^= (1 << ((temp-(1+4))+k*8));
                }
                printf("detected\n");
                printf("addr = 0x%08X\n", addr);
                printf("Data:               ");
                printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
                printf("\n");
                printf("Data_p_r:           ");
                printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data_p_r>>24), BYTE_TO_BINARY(data_p_r>>16), BYTE_TO_BINARY(data_p_r>>8), BYTE_TO_BINARY(data_p_r));
                printf("\n");
                printf("Par= ");
                printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity));
                printf("\n");
                printf("ParN=");
                printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(parity_new));
                printf("\n");
                printf("Syndrome= ");
                printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(scbspasp));
                printf("\n");
                printf("using hamming\n");
                printf("DataCorrected:      ");
                printf(BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data>>24), BYTE_TO_BINARY(data>>16), BYTE_TO_BINARY(data>>8), BYTE_TO_BINARY(data));
                printf("\n");
                *addr = data;
                *addr_p = data_p;
            } else if ( !(1 & data_p_r>>(k*5+4)) && ((data_p_r>>(k*5)) & 0xF) ){
                //hamming double
                error = 2;
            }
        }

    }

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
            //printf("addr = %u\n", addr);

            printf("addr = 0x%08X\n", addr+addr_start);
            printf("value = 0x%08X\n", *(addr_start+addr));

            int bit=0;
            bit = randomn(64);
            printf("instr_bit = %d\n", bit);
            if(bit<32){
                *(addr_start+addr) ^= (1 << (bit));
            } else if(bit<64){
                instr_p[addr] ^= (1 << (bit-32));
            } else if(bit<65){
                parity_instr[addr] ^= (1 << (bit-64));
            }
        } else {
            int v_pos = randomn(ELEMENTS);
            int bit=0;
            bit = randomn(64);
            printf("addr = 0x%08X\n", &v[v_pos]);
            printf("value = %u\n", v[v_pos]);
            printf("v_bit = %d\n", bit);

            if(bit<32){
                v[v_pos] ^= (1 << (bit));
            } else if(bit<64){
                v_p[v_pos] ^= (1 << (bit-32));
            } else if(bit<65){
                parity_v[v_pos] ^= (1 << (bit-64));
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
