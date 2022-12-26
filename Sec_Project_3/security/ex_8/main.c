#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c \n"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

uint32_t secure_hash_function(uint32_t x){
	// From https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	// The second line further mixes the bits. Using just one multiplication isn't as good
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

struct key{
	uint32_t *X0;
	uint32_t *X1;
	uint32_t length_t;
};

void generate(struct key* public_key, struct key* private_key,const uint32_t length){
	private_key->length_t = length;
	public_key->length_t = length;
	private_key->X0 = malloc (length * sizeof(uint32_t));
	private_key->X1 = malloc (length * sizeof(uint32_t));
	public_key->X0 = malloc (length * sizeof(uint32_t));
	public_key->X1 = malloc (length * sizeof(uint32_t));
	
	for(int i = 0;i<length;i++){
		private_key->X0[i] = (uint32_t) rand();
		private_key->X1[i] = (uint32_t) rand();

		public_key->X0[i] = secure_hash_function(private_key->X0[i]);
		public_key->X1[i] = secure_hash_function(private_key->X1[i]);
	}
}

void destroy_keys(struct key* public_key, struct key* private_key){
	free (private_key->X0);
	free (private_key->X1);
	free (public_key->X0);
	free (public_key->X1);
}

void sign(struct key* private_key, uint32_t message, uint32_t* signature){
	// There are only two possible messages, let’ say “0” and “1”. 
	for(int i=0; i< private_key->length_t; i++){
		signature[i] = ((message >> i) & 1) ? private_key->X0[i] : private_key->X1[i];
	}
}

int verify(uint32_t message, uint32_t* signature, struct key* public_key){
	for(int i = 0; i< public_key->length_t; i++){
		//check if i-th value of signature matches hash of public key (index determined by message-bit at position i)
		if((message >> i) & 1){
			if(secure_hash_function(signature[i]) != public_key->X0[i]){
				printf("\nFailed to verify signature at %dth bit. Excpected %u, Got %u\n",i, signature[i], public_key->X0[i]);
				return 0;
			}
		}else{
			if(secure_hash_function(signature[i]) != public_key->X1[i]){
				printf("\nFailed to verify signature at %dth bit: Excpected %u, Got %u\n",i, signature[i], public_key->X1[i]);
				return 0;
			}
		}
	}
	return 1;
}

int main(int argc , void *argv[]){
	
	if (argc != 3 ) {
		printf ("Please Define message and key size \n");
		return 1;
	}
	
	const uint32_t message = strtol (argv[1], NULL, 2);
	const uint32_t key_length = strtol (argv[2], NULL, 10);

	srand(time(NULL));

	uint32_t signature[key_length];
	struct key public_key;
	struct key private_key;
	
	printf("Message: %u \n", message);
	printf("Message in Binary: "BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(message));
	printf("Key Length: %d \n", key_length);


	generate(&public_key , &private_key , key_length);

	sign(&private_key, message, signature);

	printf("Signature: ");
	for(int i=0; i<key_length; i++)
		printf("%u ", signature[i]);
	if ( verify(message, signature, &public_key)) {
		printf("\n Success Signature is Valid \n");
	} else {
		printf("\n Error Signature is NOT Valid \n");
	}

	printf("**** Signing again with different private key **** \n");
	private_key.X0[key_length/2] = (uint32_t) rand();
	private_key.X1[key_length/2] = (uint32_t) rand();

	sign(&private_key, message, signature);

	printf("Signature: ");
	for(int i=0; i<key_length; i++)
		printf("%u ", signature[i]);
	if ( verify(message, signature, &public_key)) {
		printf("\n Success Signature is Valid \n");
	} else {
		printf("\n Error Signature is NOT Valid \n");
	}
	
	destroy_keys(&public_key , &private_key);

}
