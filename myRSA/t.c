/*
	*				help:�����ĵ�
	-k				key:��ͬĿ¼��������Կ�ļ�
	-pube (DIRs)	encrypt:��Կ �����ļ�/�ݹ��������Ŀ¼
	-pubd (DIRs)	decrypt:��Կ �����ļ�/�ݹ��������Ŀ¼
	-prie (DIRs)	encrypt:˽Կ �����ļ�/�ݹ��������Ŀ¼
	-prid (DIRs)	decrypt:˽Կ �����ļ�/�ݹ��������Ŀ¼
*/
#include<stdio.h>
#include<string.h>
#include<io.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/applink.c>
#define PubKeyFileName "RSA_Public"	//��Կ�ļ���(���뺬��Public)
#define PriKeyFileName "RSA_Private"//˽Կ�ļ���(���뺬��Private)
#define KeyBit 2048	//��Կλ��
#define E 65537	//E
#define RSAsize (KeyBit / 8)//���ĳ���
#define RSA_In_Size (RSAsize - 11)//���ζ����ļ����ݵ����������ֽ���(ʹ��RSA_PKCS1_PADDINGʱ-11)

int ShowHelp(void)
{//��ʾ�����ĵ�
	printf("*:�����ĵ�\n");
	printf("-k:��ͬĿ¼��������Կ�ļ�\n");
	printf("-pube(DIRs):��Կ �����ļ�/�ݹ��������Ŀ¼\n");
	printf("-pubd(DIRs):��Կ �����ļ�/�ݹ��������Ŀ¼\n");
	printf("-prie(DIRs):˽Կ �����ļ�/�ݹ��������Ŀ¼\n");
	printf("-prid(DIRs):˽Կ �����ļ�/�ݹ��������Ŀ¼\n");
	printf("�벻Ҫ�Դ��ļ�ִ�м���/���ܲ���\nʹ�ù�Կ��˽Կʱ�뽫��Կ�ļ���˽Կ�ļ��뱾��������ͬһĿ¼�£�\n");
	printf("!!!���ܽ��ܹ������벻Ҫ�˳����򣬱������ݶ�ʧ!!!\n");
	return 0;
}
int CheckFileExist(char *Type)
{//���ָ��������Կ�Ƿ��Ѵ��ڣ�0:�ļ������� 1:�ļ����ڲ��������� 2:�ļ����ڲ�����
	FILE *tfp = NULL;
	char ch;

	tfp = fopen(Type, "r");
	if (tfp)
	{//��Կ�ļ��Ѵ���
		if (strstr(Type,"Public"))
			printf("��Կ�ļ��Ѵ��ڣ��Ƿ���ȫ���ǣ�[y/n]");
		else
			printf("˽Կ�ļ��Ѵ��ڣ��Ƿ���ȫ���ǣ�[y/n]");
		ch = getchar();
		getchar();
		if (ch == 'N' || ch == 'n')
			return 2;//��Կ������
		fclose(tfp);
		return 1;//��Կ����
	}
	return 0;//��Կ�ļ�������
}
int ReleaseKey(void)
{//�ͷ���Կ�ļ�
	RSA *Key = NULL;
	FILE *fp_RSAPUB = NULL, *fp_RSAPRI = NULL;
	int WritePUB = 1, WritePri = 1;//����д�빫Կ��˽Կ��־
	char ch;

	if (CheckFileExist(PubKeyFileName) == 2)
		WritePUB = 0;//��д�빫Կ
	if (CheckFileExist(PriKeyFileName) == 2)
		WritePri = 0;//��д��˽Կ
	if (WritePUB != WritePri)
	{
		printf("!!!����д��(����)ĳһ����Կ���ܵ��º����ļ��ܻ���ܳ���!!!\n�Ƿ������[y/n]");
		ch = getchar();
		if (ch == 'n' || ch == 'N')
			return 1;
	}
	if (WritePUB || WritePri)
	{
		printf("--����RSA��Կ��...\n");
		Key = RSA_generate_key(KeyBit, E, NULL, NULL);//����RSA��Կ��˽Կ��2048bits��e=65537
		RSA_print_fp(stdout, Key, 0);//��ʾRSA���
		printf("--����RSA��Կ��...OK\n");
		if (WritePUB)
		{
			printf("--����RSA��Կ�ļ�(%s)...\n", PubKeyFileName);
			fp_RSAPUB = fopen(PubKeyFileName, "w");
			PEM_write_RSAPublicKey(fp_RSAPUB, Key);//���ɹ�Կ�ļ�
			fclose(fp_RSAPUB);
			printf("--����RSA��Կ�ļ�(%s)...OK\n", PubKeyFileName);
		}
		if (WritePri)
		{
			printf("--����RSA˽Կ�ļ�(%s)...\n", PriKeyFileName);
			fp_RSAPRI = fopen(PriKeyFileName, "w");
			PEM_write_RSAPrivateKey(fp_RSAPRI, Key, NULL, NULL, 0, NULL, NULL);//����˽Կ�ļ�
			fclose(fp_RSAPRI);
			printf("--����RSA˽Կ�ļ�(%s)...OK\n", PriKeyFileName);
		}
		RSA_free(Key);
	}

	return 0;
}
int EnSingleFile(char *FilePath, RSA *memRSA, int Type)
{//���ܵ����ļ���Type:	0:��Կ���� 1:˽Կ����
	unsigned char buf_File[RSA_In_Size] = { 0 };//���������ݻ�����
	unsigned char buf_Result[RSAsize] = { 0 };//���ܽ��������
	unsigned char FileName[FILENAME_MAX] = { 0 };//�ļ���
	long FileSize;//�ļ��ֽ���
	char *pstr = NULL;//ָ���ļ����ַ���
	FILE *fp = NULL;

	strcpy(FileName, (pstr = strrchr(FilePath, '\\')) ? pstr+1 : FilePath);//��ȡ�ļ���
	fp = fopen(FilePath, "rb");
	FileSize = filelength(fileno(fp));//��ȡ�ļ��ֽ���
	printf("--[%s] [%ld �ֽ�] ����...", FileName, FileSize);
	fread(buf_File, 1, FileSize, fp);//��ȡ�ļ����ݵ�������
	if (!Type)//��buf_File�е����ݼ��ܷ���buf_Result
		RSA_public_encrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	else
		RSA_private_encrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	fclose(fp);

	fp = fopen(FilePath, "wb");
	fwrite(buf_Result, 1, RSAsize, fp);//����д������
	fclose(fp);
	printf("OK\n");

	return 0;
}
int DeSingleFile(char *FilePath, RSA *memRSA, int Type)
{//���ܵ����ļ���Type:	0:��Կ���� 1:˽Կ����
	unsigned char buf_File[RSAsize] = { 0 };//���������ݻ�����
	unsigned char buf_Result[RSAsize] = { 0 };//���ܽ��������
	unsigned char FileName[FILENAME_MAX] = { 0 };//�ļ���
	long FileSize;//�ļ��ֽ���
	char *pstr = NULL;//ָ���ļ����ַ���
	FILE *fp = NULL;

	strcpy(FileName, (pstr = strrchr(FilePath, '\\')) ? pstr + 1 : FilePath);//��ȡ�ļ���
	fp = fopen(FilePath, "rb");
	FileSize = filelength(fileno(fp));//��ȡ�ļ��ֽ���
	printf("--[%s] [%ld �ֽ�] ����...", FileName, FileSize);
	fread(buf_File, 1, FileSize, fp);//��ȡ�ļ����ݵ�������
	if (!Type)//��buf_File�е����ݽ��ܷ���buf_Result
		RSA_public_decrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	else
		RSA_private_decrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	fclose(fp);

	fp = fopen(FilePath, "wb");
	fwrite(buf_Result, 1, strlen(buf_Result), fp);//����д������
	fclose(fp);
	printf("OK\n");

	return 0;
}
int R_ENorDE(char *FilePath, RSA *memRSA, int Type, int Mode)
{//�ݹ鱾�壬���ܻ���ܣ�Type��	0:��Կ 1:˽Կ��Mode:	0:���� 1:����
	unsigned char Fstr[_MAX_PATH] = { 0 };//�ļ�/Ŀ¼����·��
	struct _finddata_t FD;
	FILE *fp = NULL;
	long handle;

	if (fp = fopen(FilePath, "rb"))
	{//·��ָ�����һ���ļ�
		fclose(fp);
		if (!Mode)
			EnSingleFile(FilePath, memRSA, Type);//����
		else
			DeSingleFile(FilePath, memRSA, Type);//����
	}
	else
	{//·��ָ��һ��Ŀ¼
		strcpy(Fstr, FilePath);
		strcat(Fstr, "\\*.*");
		handle = _findfirst(Fstr, &FD);
		if (handle == -1)
		{
			printf("--[%s] ����ʧ��\n", Fstr);
			return 1;//����Ŀ¼ʧ��
		}
		do
		{
			if (strcmp(FD.name, ".") == 0 || strcmp(FD.name, "..") == 0)
				continue;//������.��..������
			memset(Fstr, 0, _MAX_FNAME);
			strcpy(Fstr, FilePath);
			strcat(Fstr, "\\");
			strcat(Fstr, FD.name);//�����ļ�����·��
			if (FD.attrib & _A_SUBDIR)
				R_ENorDE(Fstr, memRSA, Type, Mode);//�Ǹ�Ŀ¼���ݹ�
			else
			{//�Ǹ��ļ�
				if (!Mode)
					EnSingleFile(Fstr, memRSA, Type);//����
				else
					DeSingleFile(Fstr, memRSA, Type);//����
			}
		} while (!_findnext(handle, &FD));
		_findclose(handle);
	}
	return 0;
}
int UseKey(char *Path[], int KeyType, int Type, int n)
{//ʹ�ù�Կ/˽Կ����/�����ļ���KeyType:	0:��Կ 1:˽Կ��Type:	0:���� 1:���ܣ�n:argv�ܳ�
	int i = 2;
	FILE *tfp = NULL;
	RSA *memRSA = NULL;

	if (!KeyType)
	{//ʹ�ù�Կ
		tfp = fopen(PubKeyFileName, "r");
		if (!tfp)
		{
			printf("--û���ҵ���Կ�ļ�����ȷ����Կ�ļ�(�ļ���[%s])�뱾����λ��ͬһĿ¼�£�\n", PubKeyFileName);
			return 1;
		}
		PEM_read_RSAPublicKey(tfp, &memRSA, NULL, NULL);//��ȡ��Կ�ļ�
		fclose(tfp);
	}
	else
	{//ʹ��˽Կ
		tfp = fopen(PriKeyFileName, "r");
		if (!tfp)
		{
			printf("--û���ҵ�˽Կ�ļ�����ȷ��˽Կ�ļ�(�ļ���[%s])�뱾����λ��ͬһĿ¼�£�\n", PriKeyFileName);
			return 1;
		}
		PEM_read_RSAPrivateKey(tfp, &memRSA, NULL, NULL);//��ȡ˽Կ�ļ�
		fclose(tfp);
	}
	
	while (i < n)
	{
		R_ENorDE(Path[i], memRSA, KeyType, Type);//ִ�еݹ�
		i++;
	}
	RSA_free(memRSA);
	return 0;
}

int main(int argc,char *argv[])
{
	/*int argc;
	char *argv[3] = { 0 };
	argv[0] = (char*)malloc(1000 * sizeof(char));
	argv[1] = (char*)malloc(1000 * sizeof(char));
	argv[2] = (char*)malloc(1000 * sizeof(char));
	argc = 3;
	strcpy(argv[0], "C:\Users\Administrator\Desktop\Test\myRSA\Debug\myRSA.exe");
	strcpy(argv[1], "-prid");
	strcpy(argv[2], "C:\\Users\\Administrator\\Desktop\\ss");*/
	if (argc == 1)
		ShowHelp();//�ղ���
	else
	{//�в���
		if (strcmp(argv[1], "-k") == 0)
			ReleaseKey();//-k		������Կ�ļ�
		else if (strcmp(argv[1], "-pube") == 0)
			UseKey(argv, 0, 0, argc);//-pube	��Կ�����ļ�
		else if (strcmp(argv[1], "-pubd") == 0)
			UseKey(argv, 0, 1, argc);//-pubd	��Կ�����ļ�
		else if (strcmp(argv[1], "-prie") == 0)
			UseKey(argv, 1, 0, argc);//-prid	˽Կ�����ļ�
		else if (strcmp(argv[1], "-prid") == 0)
			UseKey(argv, 1, 1, argc);//-prid	˽Կ�����ļ�
		else
			ShowHelp();//��Ч����
	}
	//system("pause");
	return 0;
}