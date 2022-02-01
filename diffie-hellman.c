#include <stdio.h>
#include <stdbool.h>
#include <openssl/bn.h>

bool Miller_Rabin_Test(BIGNUM *n, BIGNUM *a);

typedef struct _b10dh_param_st {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
}BOB10_DH_PARAM;

typedef struct _b10dh_keypair_st {
    BIGNUM *prk;
    BIGNUM *puk;
}BOB10_DH_KEYPAIR;

BOB10_DH_PARAM *BOB10_DH_PARAM_new() 
{
    struct _b10dh_param_st *dh_param = malloc(sizeof(BOB10_DH_PARAM));
    
    dh_param->p = BN_new();
    dh_param->q = BN_new();
    dh_param->g = BN_new();

    return dh_param;
}

BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new() 
{
    struct _b10dh_keypair_st *dh_keypair = malloc(sizeof(BOB10_DH_KEYPAIR));

    dh_keypair->prk = BN_new();
    dh_keypair->puk = BN_new();

    return dh_keypair;
}

int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp)
{
    if(b10dhp != NULL)
        BN_free(b10dhp->p);
        BN_free(b10dhp->q);
        BN_free(b10dhp->g);

        free(b10dhp);

    return 0;
}

int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk)
{
    if(b10dhk != NULL)
        BN_free(b10dhk->prk);
        BN_free(b10dhk->puk);

        free(b10dhk);

    return 0;
}

int BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits)
{
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *j = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *zero = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    int i = 0;
    BN_zero(zero);
    int is_zero = 0;

    // q의 Miller_Rabin_Test 10회
    while(true) {
        BN_rand(q, qBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        BN_rand_range(a, q);

        for(i=0; i<10; i++) {
            if(Miller_Rabin_Test(q, a))    { continue; }
            else    { break; }
        }

        if(i == 10) { break; }
    }

    int jBits = pBits - qBits;
    i = 0;
    is_zero = 0;

    // p의 Miller_Rabin_Test 3회
    while(true) {
        // j는 홀수로 난수 뽑은 후 + 1을 통해 짝수로 생성
        BN_rand(j, jBits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
        BN_add(j, j, BN_value_one());

        // p = q * j + 1
        BN_mul(p, q, j, ctx);
        BN_add(p, p, BN_value_one());
        
        BN_rand_range(a, p);

        for(i=0; i<3; i++) {
            if(Miller_Rabin_Test(p, a))    { continue; }
            else    { break; }
        }

        if(i == 3) { break; }
    }

    BN_copy(dhp->p, p);
    BN_copy(dhp->q, q);

    return 0;
}

int BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp)
{
    BIGNUM *g = BN_new();
    BIGNUM *zero = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *p_sub_1 = BN_new();
    BIGNUM *p_sub_1rs = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // p_sub_1 = p-1
    BN_sub(p_sub_1, dhp->p, BN_value_one());

    BN_div(k, NULL, p_sub_1, dhp->q, ctx);
    BN_rand_range(g, dhp->p);

    BN_mod_exp(g, g, k, dhp->p, ctx);
    dhp->g = g;

    return 0;
}

int BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk,BOB10_DH_PARAM *dhp)
{
    BIGNUM *secret = BN_new();
    BIGNUM *compute_Y = BN_new();
    BIGNUM *a = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *zero = BN_new();

    bool is_zero = false;
    BN_zero(zero);

    BN_rand(secret, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
    BN_rand_range(a, secret);

    int i = 0;
    while(i < 3) {
        if(!Miller_Rabin_Test(secret, a))    { i++; }
        else    { break; }
    }

    BN_mod_exp(compute_Y, dhp->g, secret, dhp->p, ctx);

    BN_copy(dhk->prk, secret);
    BN_copy(dhk->puk, compute_Y);
}

int BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp)
{
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(sharedSecret, peerKey, dhk->prk, dhp->p, ctx);
}

bool Miller_Rabin_Test(BIGNUM *n, BIGNUM *a)
{
    BIGNUM *zero = BN_new();
    BIGNUM *_1 = BN_new();
    BIGNUM *n_sub_1 = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *exp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // n_sub_1과 d는 n-1로 설정
    BN_sub(n_sub_1, n, BN_value_one());
    BN_sub(d, n, BN_value_one());

    int s = 0;
    // n-1 = 2^s * d 로 표현
    while(true) {
        if(!BN_is_odd(d))   { s++; BN_rshift1(d,d); }
        else    { break; }
    }

    BN_zero(zero);
    int k = 0;

    // result = a^(n-1) % n, d = (n-1)
    BN_mod_exp(result, a, d, n, ctx);

    if(!BN_cmp(result, _1) || !BN_cmp(result, BN_value_one()))   { return true; }

    else {
        while(true) {
            if( k < s ) {
                BN_lshift1(d, d);
                k++;

                // result = a^d % n
                BN_mod_exp(result, a, d, n, ctx);
                if(!BN_cmp(result, _1))   { return true; }
                else { continue; }
            }
        break;
        }   
    }

    return false;
}

int main (int argc, char *argv[]) 
{
    BIGNUM *sharedSecret = BN_new();
    BOB10_DH_PARAM *dhp = BOB10_DH_PARAM_new();
    BOB10_DH_KEYPAIR *aliceK = BOB10_DH_KEYPAIR_new();
    BOB10_DH_KEYPAIR *bobK = BOB10_DH_KEYPAIR_new();

    BOB10_DH_ParamGenPQ(dhp, 2048, 256);
    printf("p=0x");BN_print_fp(stdout,dhp->p);printf("\n");
    printf("q=0x");BN_print_fp(stdout,dhp->q);printf("\n");
	
    BOB10_DH_ParamGenG(dhp);
    printf("g=0x");BN_print_fp(stdout,dhp->g);printf("\n");

    BOB10_DH_KeypairGen(aliceK,dhp);
    printf("alicePuk=0x");BN_print_fp(stdout,aliceK->puk);printf("\n");
    printf("alicePrk=0x");BN_print_fp(stdout,aliceK->prk);printf("\n");

    BOB10_DH_KeypairGen(bobK,dhp);
    printf("bobPuk=0x");BN_print_fp(stdout,bobK->puk);printf("\n");
    printf("bobPrk=0x");BN_print_fp(stdout,bobK->prk);printf("\n");

    BOB10_DH_Derive(sharedSecret, bobK->puk, aliceK, dhp);
    printf("SS1=0x");BN_print_fp(stdout,sharedSecret);printf("\n");
    BOB10_DH_Derive(sharedSecret, aliceK->puk, bobK, dhp);
    printf("SS2=0x");BN_print_fp(stdout,sharedSecret);printf("\n");

    BOB10_DH_PARAM_free(dhp);
    BOB10_DH_KEYPAIR_free(aliceK);
    BOB10_DH_KEYPAIR_free(bobK);
    BN_free(sharedSecret);

    return 0;
}