/*
	*				help:帮助文档
	-k				key:相同目录下生成密钥文件
	-pube (DIRs)	encrypt:公钥 加密文件/递归加密整个目录
	-pubd (DIRs)	decrypt:公钥 解密文件/递归解密整个目录
	-prie (DIRs)	encrypt:私钥 加密文件/递归加密整个目录
	-prid (DIRs)	decrypt:私钥 解密文件/递归解密整个目录
*/
#include<stdio.h>
#include<string.h>
#include<io.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<openssl/applink.c>
#define PubKeyFileName "RSA_Public"	//公钥文件名(必须含有Public)
#define PriKeyFileName "RSA_Private"//私钥文件名(必须含有Private)
#define KeyBit 2048	//密钥位数
#define E 65537	//E
#define RSAsize (KeyBit / 8)//密文长度
#define RSA_In_Size (RSAsize - 11)//单次读入文件内容到缓冲区的字节数(使用RSA_PKCS1_PADDING时-11)

int ShowHelp(void)
{//显示帮助文档
	printf("*:帮助文档\n");
	printf("-k:相同目录下生成密钥文件\n");
	printf("-pube(DIRs):公钥 加密文件/递归加密整个目录\n");
	printf("-pubd(DIRs):公钥 解密文件/递归解密整个目录\n");
	printf("-prie(DIRs):私钥 加密文件/递归加密整个目录\n");
	printf("-prid(DIRs):私钥 解密文件/递归解密整个目录\n");
	printf("请不要对大文件执行加密/解密操作\n使用公钥或私钥时请将公钥文件或私钥文件与本程序置于同一目录下！\n");
	printf("!!!加密解密过程中请不要退出程序，避免数据丢失!!!\n");
	return 0;
}
int CheckFileExist(char *Type)
{//检查指定类型密钥是否已存在，0:文件不存在 1:文件存在并决定覆盖 2:文件存在不覆盖
	FILE *tfp = NULL;
	char ch;

	tfp = fopen(Type, "r");
	if (tfp)
	{//密钥文件已存在
		if (strstr(Type,"Public"))
			printf("公钥文件已存在，是否完全覆盖？[y/n]");
		else
			printf("私钥文件已存在，是否完全覆盖？[y/n]");
		ch = getchar();
		getchar();
		if (ch == 'N' || ch == 'n')
			return 2;//密钥不覆盖
		fclose(tfp);
		return 1;//密钥覆盖
	}
	return 0;//密钥文件不存在
}
int ReleaseKey(void)
{//释放密钥文件
	RSA *Key = NULL;
	FILE *fp_RSAPUB = NULL, *fp_RSAPRI = NULL;
	int WritePUB = 1, WritePri = 1;//决定写入公钥、私钥标志
	char ch;

	if (CheckFileExist(PubKeyFileName) == 2)
		WritePUB = 0;//不写入公钥
	if (CheckFileExist(PriKeyFileName) == 2)
		WritePri = 0;//不写入私钥
	if (WritePUB != WritePri)
	{
		printf("!!!单独写入(覆盖)某一种密钥可能导致后续的加密或解密出错!!!\n是否继续？[y/n]");
		ch = getchar();
		if (ch == 'n' || ch == 'N')
			return 1;
	}
	if (WritePUB || WritePri)
	{
		printf("--生成RSA密钥对...\n");
		Key = RSA_generate_key(KeyBit, E, NULL, NULL);//生成RSA公钥、私钥，2048bits，e=65537
		RSA_print_fp(stdout, Key, 0);//显示RSA情况
		printf("--生成RSA密钥对...OK\n");
		if (WritePUB)
		{
			printf("--生成RSA公钥文件(%s)...\n", PubKeyFileName);
			fp_RSAPUB = fopen(PubKeyFileName, "w");
			PEM_write_RSAPublicKey(fp_RSAPUB, Key);//生成公钥文件
			fclose(fp_RSAPUB);
			printf("--生成RSA公钥文件(%s)...OK\n", PubKeyFileName);
		}
		if (WritePri)
		{
			printf("--生成RSA私钥文件(%s)...\n", PriKeyFileName);
			fp_RSAPRI = fopen(PriKeyFileName, "w");
			PEM_write_RSAPrivateKey(fp_RSAPRI, Key, NULL, NULL, 0, NULL, NULL);//生成私钥文件
			fclose(fp_RSAPRI);
			printf("--生成RSA私钥文件(%s)...OK\n", PriKeyFileName);
		}
		RSA_free(Key);
	}

	return 0;
}
int EnSingleFile(char *FilePath, RSA *memRSA, int Type)
{//加密单个文件，Type:	0:公钥加密 1:私钥加密
	unsigned char buf_File[RSA_In_Size] = { 0 };//待加密内容缓冲区
	unsigned char buf_Result[RSAsize] = { 0 };//加密结果缓冲区
	unsigned char FileName[FILENAME_MAX] = { 0 };//文件名
	long FileSize;//文件字节数
	char *pstr = NULL;//指向文件名字符串
	FILE *fp = NULL;

	strcpy(FileName, (pstr = strrchr(FilePath, '\\')) ? pstr+1 : FilePath);//获取文件名
	fp = fopen(FilePath, "rb");
	FileSize = filelength(fileno(fp));//获取文件字节数
	printf("--[%s] [%ld 字节] 加密...", FileName, FileSize);
	fread(buf_File, 1, FileSize, fp);//读取文件内容到缓冲区
	if (!Type)//将buf_File中的内容加密放入buf_Result
		RSA_public_encrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	else
		RSA_private_encrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	fclose(fp);

	fp = fopen(FilePath, "wb");
	fwrite(buf_Result, 1, RSAsize, fp);//覆盖写入密文
	fclose(fp);
	printf("OK\n");

	return 0;
}
int DeSingleFile(char *FilePath, RSA *memRSA, int Type)
{//解密单个文件，Type:	0:公钥解密 1:私钥解密
	unsigned char buf_File[RSAsize] = { 0 };//待解密内容缓冲区
	unsigned char buf_Result[RSAsize] = { 0 };//解密结果缓冲区
	unsigned char FileName[FILENAME_MAX] = { 0 };//文件名
	long FileSize;//文件字节数
	char *pstr = NULL;//指向文件名字符串
	FILE *fp = NULL;

	strcpy(FileName, (pstr = strrchr(FilePath, '\\')) ? pstr + 1 : FilePath);//获取文件名
	fp = fopen(FilePath, "rb");
	FileSize = filelength(fileno(fp));//获取文件字节数
	printf("--[%s] [%ld 字节] 解密...", FileName, FileSize);
	fread(buf_File, 1, FileSize, fp);//读取文件内容到缓冲区
	if (!Type)//将buf_File中的内容解密放入buf_Result
		RSA_public_decrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	else
		RSA_private_decrypt(FileSize, buf_File, buf_Result, memRSA, RSA_PKCS1_PADDING);
	fclose(fp);

	fp = fopen(FilePath, "wb");
	fwrite(buf_Result, 1, strlen(buf_Result), fp);//覆盖写入明文
	fclose(fp);
	printf("OK\n");

	return 0;
}
int R_ENorDE(char *FilePath, RSA *memRSA, int Type, int Mode)
{//递归本体，加密或解密，Type：	0:公钥 1:私钥，Mode:	0:加密 1:解密
	unsigned char Fstr[_MAX_PATH] = { 0 };//文件/目录绝对路径
	struct _finddata_t FD;
	FILE *fp = NULL;
	long handle;

	if (fp = fopen(FilePath, "rb"))
	{//路径指向的是一个文件
		fclose(fp);
		if (!Mode)
			EnSingleFile(FilePath, memRSA, Type);//加密
		else
			DeSingleFile(FilePath, memRSA, Type);//解密
	}
	else
	{//路径指向一个目录
		strcpy(Fstr, FilePath);
		strcat(Fstr, "\\*.*");
		handle = _findfirst(Fstr, &FD);
		if (handle == -1)
		{
			printf("--[%s] 查找失败\n", Fstr);
			return 1;//查找目录失败
		}
		do
		{
			if (strcmp(FD.name, ".") == 0 || strcmp(FD.name, "..") == 0)
				continue;//遍历到.和..则跳过
			memset(Fstr, 0, _MAX_FNAME);
			strcpy(Fstr, FilePath);
			strcat(Fstr, "\\");
			strcat(Fstr, FD.name);//生成文件绝对路径
			if (FD.attrib & _A_SUBDIR)
				R_ENorDE(Fstr, memRSA, Type, Mode);//是个目录，递归
			else
			{//是个文件
				if (!Mode)
					EnSingleFile(Fstr, memRSA, Type);//加密
				else
					DeSingleFile(Fstr, memRSA, Type);//解密
			}
		} while (!_findnext(handle, &FD));
		_findclose(handle);
	}
	return 0;
}
int UseKey(char *Path[], int KeyType, int Type, int n)
{//使用公钥/私钥加密/解密文件，KeyType:	0:公钥 1:私钥，Type:	0:加密 1:解密，n:argv总长
	int i = 2;
	FILE *tfp = NULL;
	RSA *memRSA = NULL;

	if (!KeyType)
	{//使用公钥
		tfp = fopen(PubKeyFileName, "r");
		if (!tfp)
		{
			printf("--没有找到公钥文件！请确保公钥文件(文件名[%s])与本程序位于同一目录下！\n", PubKeyFileName);
			return 1;
		}
		PEM_read_RSAPublicKey(tfp, &memRSA, NULL, NULL);//读取公钥文件
		fclose(tfp);
	}
	else
	{//使用私钥
		tfp = fopen(PriKeyFileName, "r");
		if (!tfp)
		{
			printf("--没有找到私钥文件！请确保私钥文件(文件名[%s])与本程序位于同一目录下！\n", PriKeyFileName);
			return 1;
		}
		PEM_read_RSAPrivateKey(tfp, &memRSA, NULL, NULL);//读取私钥文件
		fclose(tfp);
	}
	
	while (i < n)
	{
		R_ENorDE(Path[i], memRSA, KeyType, Type);//执行递归
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
		ShowHelp();//空参数
	else
	{//有参数
		if (strcmp(argv[1], "-k") == 0)
			ReleaseKey();//-k		生成密钥文件
		else if (strcmp(argv[1], "-pube") == 0)
			UseKey(argv, 0, 0, argc);//-pube	公钥加密文件
		else if (strcmp(argv[1], "-pubd") == 0)
			UseKey(argv, 0, 1, argc);//-pubd	公钥解密文件
		else if (strcmp(argv[1], "-prie") == 0)
			UseKey(argv, 1, 0, argc);//-prid	私钥加密文件
		else if (strcmp(argv[1], "-prid") == 0)
			UseKey(argv, 1, 1, argc);//-prid	私钥解密文件
		else
			ShowHelp();//无效输入
	}
	//system("pause");
	return 0;
}