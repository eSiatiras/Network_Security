#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <assert.h>
#include <string.h>


char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }

    }

    return result;
}

int 
main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("1st Arg should be the encrypted passwd from the shadowfile \n");
		printf("2st Arg should be the one possible password \n");
        return 1;
    }

		
	char *enc_passwd  = argv[1]; //Gets second value as hashed password
	char *toCrack = argv[2]; //Gets third value as hashed password
    char** tokens;
	
	printf("Encrypted Passwd: %s\n", enc_passwd);
	printf("Guessed Passwd:   %s\n", toCrack);
	
	char *password = malloc(sizeof(char*) * strlen(enc_passwd));
	
	memcpy(password,enc_passwd,strlen(enc_passwd));

    tokens = str_split(password, '$');

    assert(tokens && "Check Input Format");
 

	printf("id = %s salt = %s encrypted = %s \n", *(tokens),  *(tokens + 1),  *(tokens + 2));
	
	 char salt [16];
	 
	 memset (salt , 0 ,strlen(salt));
	
	strcat (salt, "$");
	strcat (salt, *(tokens));
	strcat (salt, "$");
	strcat (salt, *(tokens + 1));
	strcat (salt, "$");
	printf("Salt = %s \n", salt);

	printf("\n");
    
    char *toCrackCiph = malloc(sizeof(char*) * strlen(enc_passwd));
	strcpy(toCrackCiph, crypt(toCrack, salt));
	
    printf("Encrypted Passwd:  %s\n", enc_passwd);
	printf("Guessed Enc Passwd:%s\n", toCrackCiph);
	
	if(strlen(toCrackCiph) != strlen(enc_passwd)) {
	
		printf("Warning Check Salt \n");
	}
	
	if ( 0 == strcmp(enc_passwd, toCrackCiph)){
		printf("Success Passwords are Equal \n");
	} else{
		printf("Warning Passwords are NOT Equal. Please reRun with another Guess\n");
	}

    return 0;
}
