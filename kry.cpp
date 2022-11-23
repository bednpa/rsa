/**
*
* Name: kry.cpp
* Desc: program for encrypting, decrypting, breaking and generating 
*       parameters of RSA asymmetric encryption algorithm
* Author: Pavel Bednar (xbedna73@stud.fit.vutbr.cz)
* Task: KRY 2nd project -- summer 2022 @ FIT BUT 
*
*/


#include <iostream>
#include <random>
#include <gmpxx.h>


#define ENCODING_SYSTEM 16  // hexadecimal output
#define MR_TIMES 10         // number of iteration of Miller-Rabin algorithm
#define FACT_LIMIT 1000000  // maximal number of trivial dividing in factorization phase


using namespace std;


/**
*
* Desc: decides if input number is prime number using Miller-Rabin algorithm
* In: number, number of algorithm iterations and random generator
* Out: true or false
*
*/
bool isPrimeMR(mpz_class p, int k, gmp_randclass *random_generator) {
    if (p == 2 || p == 3) {
        return true;
    }
    if (p % 2 == 0) {
        return false;
    }
    mpz_class rr;
    mpz_class d = p - 1;
    mpz_class pp;
    mpz_class r = 0;
    mpz_class repeat_r;
    mpz_class a;
    mpz_class x;
    mpz_class xx;
    while (d % 2 == 0) {
        d = d / 2;
        r++;
    }
    mpz_ui_pow_ui(rr.get_mpz_t(), 2, r.get_ui());
    bool possible_prime = true;
    while(k && possible_prime) {
        possible_prime = false;
        a = random_generator->get_z_range(p-3);
        a = a + 2;
        mpz_pow_ui(x.get_mpz_t(), a.get_mpz_t(), d.get_ui());
        x = x % p;
        if (x == 1 || x == p - 1) {
            k--;
            possible_prime = true;
            continue;
        }
        repeat_r = r - 1;
        while(repeat_r) {
            x = (x * x) % p;
            if (x == p - 1) {
                possible_prime = true;
                break;
            }
            repeat_r--;
        }
        k--;
    }
    return possible_prime;
}


/**
*
* Desc: computes multiplicative inverse of greater input mod smaller input,
*       using Extended Eulers Method
* In: two numbers
* Out: multiplicative inverse of greater input mod smaller input
*
*/
mpz_class computeInverse(mpz_class a, mpz_class b) {
    mpz_class c = 0;
    if (a < b) {
        c = a;
        a = b;
        b = c;
    }
    mpz_class result_array[] = {a, b, -1, -1, 1, 0, 0, 1};
    mpz_class result;
    while(result_array[1] > 0) {
        mpz_class new_array[8];
        new_array[2] = result_array[0] / result_array[1];
        new_array[3] = result_array[0] % result_array[1];
        new_array[4] = result_array[5];
       	new_array[5] = result_array[4] - new_array[2] * result_array[5];
       	new_array[6] = result_array[7];
       	new_array[7] = result_array[6] - new_array[2] * result_array[7];
        new_array[0] = result_array[1];
        new_array[1] = new_array[3];
        for (int i=0; i<8; i++) {
            result_array[i] = new_array[i];
        }
    }
    if (result_array[6] < 0) {
        result = a + result_array[6];
    } else {
        result = result_array[6];
    }
    return result;
}    


/**
*
* Desc: computes greatest common divider of two numbers
* In: two numbers
* Out: greatest common divider of input
*
*/
mpz_class computeGCD(mpz_class a, mpz_class b) {
   mpz_class c = 0;
    if (a < b) {
        c = a;
	a = b;
	b = c;
    }
    mpz_class result_array[] = {a, b, -1, -1, 1, 0, 0, 1};
    while(result_array[1] > 0) {
        mpz_class new_array[8];
        new_array[2] = result_array[0] / result_array[1];
        new_array[3] = result_array[0] % result_array[1];
        new_array[4] = result_array[5];
        new_array[5] = result_array[4] - new_array[2] * result_array[5];
        new_array[6] = result_array[7];
        new_array[7] = result_array[6] - new_array[2] * result_array[7];
        new_array[0] = result_array[1];
        new_array[1] = new_array[3];
        for (int i=0; i<8; i++) {
            result_array[i] = new_array[i];
        }
    }
    mpz_class result = result_array[0];
    return result;
}


/**
*
* Desc: computes e
* In: n, random generator
* Out: a
*
*/
mpz_class getE(mpz_class phi_n, gmp_randclass *random_generator) {
    mpz_class a;
    bool is_one = false;
    while(!is_one) {
        a = random_generator->get_z_range(phi_n);
        a++;
        mpz_class x = computeGCD(phi_n, a);
        if (x == 1) {
            is_one = true;
        } else {
            is_one = false;
        }
    }
    return a;
}


/**
*
* Desc: function that generated RSA private and public keys 
* In: bit size of two prime numbers and random generator
* Out: p, q, n, e, d
*
*/
auto generateKeys(mpz_class bit_size, gmp_randclass *random_generator) {
    mpz_class aa;
    mpz_class aaa;
    mpz_ui_pow_ui(aa.get_mpz_t(), 2, bit_size.get_ui()-1);
    mpz_ui_pow_ui(aaa.get_mpz_t(), 2, bit_size.get_ui());
    aaa--;
    mpz_class a = 2;
    mpz_class b = 2;
    mpz_class n = 0;
    while (n < aa || n >= aaa || !isPrimeMR(a, MR_TIMES, random_generator) || !isPrimeMR(b, MR_TIMES, random_generator)) {
        a = random_generator->get_z_bits(bit_size/2+1);
        b = random_generator->get_z_bits(bit_size-bit_size/2+1);
        n = a*b; 
    }
    mpz_class phi_n = (a-1)*(b-1);
    mpz_class e = getE(phi_n, random_generator);
    mpz_class d = computeInverse(e, phi_n);
    struct result {mpz_class p; mpz_class q; mpz_class n; mpz_class e; mpz_class d;};
    return result {a, b, n, e, d};
}


/**
*
* Desc: RSA encrypt function
* In: e, n, m
* Out: encrypted message
*
*/
mpz_class encrypt(mpz_class e, mpz_class n, mpz_class m) {
    mpz_class cc;
    mpz_class c;
    mpz_pow_ui(cc.get_mpz_t(), m.get_mpz_t(), e.get_ui());
    c = cc % n;
    return c;
}


/**
*
* Desc: RSA decrypt function
* In: d, n, c
* Out: decrypted message
*
*/
mpz_class decrypt(mpz_class d, mpz_class n, mpz_class c) {
    mpz_class mm;
    mpz_class m;
    mpz_pow_ui(mm.get_mpz_t(), c.get_mpz_t(), d.get_ui());
    m =	mm % n;
    return m;
}


/**
*
* Desc: helper function for Fermats Factorization, 
*       decides whether input is equal to some n*n
* In:
* Out:
*
*/
bool isSquare(mpz_class x) { 
    mpz_class left = 1;
    mpz_class right = x;
    while (left <= right) {
        mpz_class mid = (left + right) / 2;
        if (mid * mid == x) {
            return true;
        }
        if (mid * mid < x) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return false;
}


/**
*
* Desc: Fermats Factorization
* In: number to be factorizated
* Out: factor of input number
*
*/
mpz_class fermatFactorization(mpz_class n) {
    mpz_class a;
    mpz_class sn = sqrt(n);
    if (sn*sn == n) {
        a = sn;
    } else {
        a = sn + 1; 
    }
    mpz_class b = a*a - n;
    while(!isSquare(b)) {
        a++;
        b = a*a - n;
    } 
    return a - sqrt(b);
}


/**
*
* Desc: helper function for Pollard Rho Method
* In:
* Out:
*
*/
mpz_class g(mpz_class x, mpz_class n) {
    return (x*x + 1) % n;
}


/**
*
* Desc: Pollard Rho Method for number factorization
* In: number to be factorizated
* Out: factor of input number or 0 if fails
*
*/
mpz_class rhoFactorization(mpz_class n) {
    mpz_class x = 2;
    mpz_class y = 2;
    mpz_class d = 1;
    while(d == 1) {
        x = g(x, n);
        y = g(g(y, n), n);
        d = computeGCD(abs(x-y), n);
    }
    if (d == n) {
        return 0;
    } else {
        return d;
    }
}


/**
*
* Desc: function for number factorization, tries Pollard Rho Method
*       if fails then does Fermats Factorization (which is much more slower)
* In: number to be factorizated
* Out: factor of input number
*
*/
mpz_class factorization(mpz_class n) {
    for (int i=2; i<=FACT_LIMIT; i++) {
        if (n % i == 0) {
            return i;
        }
    }
    mpz_class x = rhoFactorization(n);
    if (x == 0) {
        return fermatFactorization(n);
    } else {
        return x;
    }
}


/**
*
* Desc: function for parsing arguments
* In: arguments
* Out:
*
*/
void argParse(int argc, char **argv) {
    random_device rd;
    gmp_randclass random_generator(gmp_randinit_default);
    random_generator.seed(rd());
    if (argc <= 2) {
        return;
    }
    string arg = argv[1];
    if (arg == "-g") {
        if (argc == 3) {
            mpz_class bit_size(argv[2]);
            auto x = generateKeys(bit_size, &random_generator);
            cout << "0x" << x.p.get_str(ENCODING_SYSTEM) << " 0x" << x.q.get_str(ENCODING_SYSTEM) << " 0x" << x.n.get_str(ENCODING_SYSTEM) << " 0x" << x.e.get_str(ENCODING_SYSTEM) << " 0x" << x.d.get_str(ENCODING_SYSTEM) << endl;
        } else {
            return;
        } 
    } else if (arg == "-e") {
       	if (argc == 5) {
            mpz_class e(argv[2]);
       	    mpz_class n(argv[3]);
       	    mpz_class m(argv[4]);
            mpz_class c = encrypt(e, n, m);
            cout << "0x" << c.get_str(ENCODING_SYSTEM) << endl;
        } else {
            return;
        }
    } else if (arg == "-d") {
        if (argc == 5) {
       	    mpz_class d(argv[2]);
            mpz_class n(argv[3]);
            mpz_class c(argv[4]);
            mpz_class m = decrypt(d, n, c);
            cout << "0x" << m.get_str(ENCODING_SYSTEM) << endl;
       	} else {
            return;
        }
    } else if (arg == "-b") {
        if (argc == 3) {
            mpz_class n(argv[2]);
            mpz_class p = factorization(n);
            cout << "0x" << p.get_str(ENCODING_SYSTEM) << endl;
       	} else {
            return;
        }
    }
    return;
}


/** 
* 
* Desc: function for testing all features combined,
*       function is not called from anywhere
* In: 
* Out: 
*
*/
void test() {
    gmp_randclass random_generator(gmp_randinit_default);
    random_device rd;
    random_generator.seed(rd());
    int bit_size = 10;

    mpz_class m = 42;
    cout << "Message: " << m.get_str(10) << endl;

    cout << "Key:" << endl;
    auto x = generateKeys(bit_size, &random_generator);
    cout << " P: " << x.p.get_str(10) << endl;
    cout << " Q: " << x.q.get_str(10) << endl;
    cout << " N: " << x.n.get_str(10) << endl;
    cout << " E: " << x.e.get_str(10) << endl;
    cout << " D: " << x.d.get_str(10) << endl;

    mpz_class c = encrypt(x.e, x.n, m);
    cout << "Encrypted message: " << c.get_str(10) << endl;
    mpz_class dm = decrypt(x.d, x.n, c);
    cout << "Decrypted message: " << dm.get_str(10) << endl;

    mpz_class f = factorization(x.n);
    cout << "Factor: " << f.get_str(10) << endl;
}


/**
*
* Desc: main function of program
* In: program arguments
* Out: return value of program
*
*/
int main(int argc, char **argv) {
    try {
	argParse(argc, argv);
    } catch (...) {
        cout << "Arguments error!" << endl;
    }
    //test(); // testing function
    return 0;
}
