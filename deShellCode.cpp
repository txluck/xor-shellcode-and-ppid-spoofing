#include <stdio.h>
#include <Windows.h>


unsigned char buf[] = "\xfc\x48\x83\xe4";
int main(int argc, char* argv[])
{
	unsigned char key[] ="master";
	unsigned char enShellCode[500];
	unsigned char deShellCode[500];
	int nLen = sizeof(buf) - 1;

	int key_len = sizeof(key) - 1;
	for (int i = 0; i < nLen; i++)
	{
		enShellCode[i] = buf[i] ^ key[i % key_len];
		printf("\\x%x", enShellCode[i]);
	}
	
	system("pause");
	return 0;
}