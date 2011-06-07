/*
 * PS2 erom dump files extractor
 * copyright (c) 2010-2011 - jimmikaelkael <jimmikaelkael@wanadoo.fr>
 *
 * licensed under WTFPL, please review the LICENSE file for details
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <config.h>


#define PROGRAM_NAME "eromdir"
#define PROGRAM_DESC "PS2 erom file extractor by jimmikaelkael"
#define PROGRAM_VER "1.4"

#define CMD_LIST	0
#define CMD_EXTRACT	1


typedef	uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;


typedef struct {
	u32 filename_hash;
	u32 fileoffset_hash; 		/* from erom start, obfuscated 		*/
	u32 filesize_hash;		/* obfuscated 				*/
	u32 next_fileoffset_hash; 	/* from erom start, obfuscated 		*/
	u32 xordata_size_hash;		/* in u32, obfuscated			*/
} erom_filedescriptor_t;

typedef struct {
	u8 *start;			/* start address of erom		*/
	erom_filedescriptor_t *fd;	/* address of 1st file descriptor	*/
	char *magic_token;
} erom_info_t;

#define HASHKEY0	0x38e38e39
#define HASHKEY1	0xaf286bcb

char *tokens[] = {			/* those tokens are used (hashed first)	*/
	" A B C",			/* to locate the 1st file descriptor	*/
	" B C D",			/* the valid token can vary from one 	*/
	" C D E",			/* PS2 model to another 		*/
	" D E F",
	" E F G",
	" F G H",
	" G H I",
	" H I J",
	" I J K",
	" J K L",
	" K L M",
	" L M N",
	" M N O",
	" N O P",
	" O P Q",
	" P Q R",
	" Q R S",
	" R S T",
	" S T U",
	" T U V",
	" U V W",
	" V W X",
	" W X Y",
	" X Y Z",
	NULL
};

char *erom_known_filenames[] = {
	"DVDELF",
	"UDFIO",
	"DVDPLA", "DVDPLE", "DVDPLU", "DVDPLJ", "DVDPLM", "DVDPLO", "DVDPLR", "DVDPLC",
	"CMN01",  "CMN02",
	"MSGB01", "MSGB02", "MSGB03", "MSGB04", "MSGB05", "MSGB06", "MSGB07", "MSGB08", 
	"MSGB09", "MSGB10", "MSGB11", "MSGB12",	"MSGB13",
	"HLPB01", "HLPB02", "HLPB03", "HLPB04",	"HLPB05", "HLPB06", "HLPB07", "HLPB08",
	"HLPB09", "HLPB10", "HLPB11", "HLPB12", "HLPB13", "HLPB14",
	"LGBB01", "LGBB02", "LGBB03", "LGBB04",	"LGBB05",
	"NUMB01", "NUMB02", "NUMB03", "NUMB04",	"NUMB05",
	"BTNB01",
	NULL
};

static erom_info_t erom_info;


/*
 * uint32 Little-Endian value read
 */
static u32 read_le_u32(u8 *buf)
{
	register u32 val;

	val = (u8)buf[0];
	val |= ((u8)buf[1] << 8);
	val |= ((u8)buf[2] << 16);
	val |= ((u8)buf[3] << 24);

	return val;
}

/*
 * uint32 Little-Endian value write
 */
static void write_le_u32(u32 val, u8 *buf)
{
	buf[0] = (u8)val;
	buf[1] = (u8)(val >> 8);
	buf[2] = (u8)(val >> 16);
	buf[3] = (u8)(val >> 24);
}

/*
 * function to get highest 32bits of mult
 */
static u32 mult_hi(u32 v1, u32 v2)
{
	register u32 a, b, c, d;
	register u32 x, y;
	register u32 LO, HI;

	a = (v1 >> 16) & 0xffff;
	b = v1 & 0xffff;
	c = (v2 >> 16) & 0xffff;
	d = v2 & 0xffff;

	LO = b * d;
	x = a * d + c * b;
	y = ((LO >> 16) & 0xffff) + x;

	LO = (LO & 0xffff) | ((y & 0xffff) << 16);
	HI = (y >> 16) & 0xffff;

	HI += a * c;

	return HI;
}

/*
 * function to get uint32 value from hash type 0
 */
static u32 get_val_from_hash0(u32 hash)
{
	register u32 v0, v1;
	register u32 ret = 0;
	register int32_t i;

	for (i=0; i<32; i+=4) {
		v0 = mult_hi(hash, HASHKEY0) >> 2;
		hash -= (((v0 << 3) + v0) << 1);
		v1 = hash - 1;
		if (v1 >= 0x0a)
			v1 = hash - 2;
		ret |= (v1 << i);
		hash = v0;
	}

	return ret;
}

/*
 * function to get uint32 value from hash type 1
 */
static u32 get_val_from_hash1(u32 hash)
{
	register u32 v0, v1;
	register u32 ret = 0;
	register int32_t i; 

	for (i=0; i<32; i+=4) {
		v0 = mult_hi(hash, HASHKEY1);
		v0 = (v0 + ((hash - v0) >> 1)) >> 4;
		v1 = (v0 << 2) + v0;
		v0 = hash - ((v1 << 2) - v0);
		v1 = v0 + 9;
		if ((v0 - 1) >= 6)
			v1 = v0 - 8;
		v0 = mult_hi(hash, HASHKEY1);
		ret |= (v1 << i);
		hash = (v0 + ((hash - v0) >> 1)) >> 4;
	}

	return ret;
}

/*
 * function to generate a uint32 hash value from a string (6 chars max)
 */
static u32 get_string_hash(char *p_str)
{
	char str[8];

	strncpy(str, p_str, 6); /* filenames must be max 6 characters in erom */
	str[6] = 0;

	u8 *p, *p2;
	register u32 hash = 0;

	for (p = (u8 *)&str[0], p2 = (u8 *)&str[6]; (uintptr_t)p < (uintptr_t)p2; p++) {
		register u32 val, byte;

		byte = *p;

		if ((u32)(byte - 'A') < '\x0d')
			val = byte - '@';
		else if ((u8)byte == '\0')
			val = '\x0e';
		else if ((u32)((u8)byte >= 'N'))
			val = byte - '?';
		else if ((u8)byte == ' ')
			val = '\x1c';
		else
			val = byte - '\x13';

		hash = (((hash << 2) + hash) << 3) + val;
	}

	return hash;
}

/*
 * function to generate an hex string from uint32 hash
 */
static void hash_to_hexstring(u32 hash, char *str)
{
	register int32_t i;

	u8 *p = (u8 *)&hash;
	p+=3;

	for (i=0; i<4; i++) {
		if ((*p >> 4) >= 0x0a)
			str[i<<1] = (*p >> 4) + 0x37;
		else
			str[i<<1] = (*p >> 4) + 0x30;
		if ((*p & 0x0f) >= 0x0a)
			str[(i<<1)+1] = (*p & 0x0f) + 0x37;
		else
			str[(i<<1)+1] = (*p & 0x0f) + 0x30;
		p--;
	}
	str[8] = 0;
}

/*
 * function to get back uint32 hash from hex string
 */
static u32 hexstring_to_hash(char *str)
{
	register int32_t i;
	register u32 hash = 0;

	u8 *p = (u8 *)str;

	for (i=7; i>=0; i--) {
		if (*p >= 0x41)
			hash |= (*p - 0x37) << (i<<2);
		else
			hash |= (*p - 0x30) << (i<<2);
		p++;
	}

	return hash;
}

/*
 * function that locate a file descriptor by filename
 */
static erom_filedescriptor_t *get_file_descriptor_by_name(char *filename)
{
	erom_filedescriptor_t *fd = erom_info.fd;

	u32 hash = get_string_hash(filename);

	while (read_le_u32((u8 *)&fd->filename_hash) != hash) {
		u32 next_entry_offset = get_val_from_hash0(read_le_u32((u8 *)&fd->next_fileoffset_hash));
		if (next_entry_offset)
			fd = (erom_filedescriptor_t *)(erom_info.start + next_entry_offset);
		else { /* no more files */
			return NULL;
		}

	}

	return fd;
}

/*
 * function that locate a file descriptor by filename hash
 */
static erom_filedescriptor_t *get_file_descriptor_by_hash(u32 hash)
{
	erom_filedescriptor_t *fd = erom_info.fd;

	while (read_le_u32((u8 *)&fd->filename_hash) != hash) {
		u32 next_entry_offset = get_val_from_hash0(read_le_u32((u8 *)&fd->next_fileoffset_hash));
		if (next_entry_offset)
			fd = (erom_filedescriptor_t *)(erom_info.start + next_entry_offset);
		else { /* no more files */
			return NULL;
		}

	}

	return fd;
}

/*
 * function that locate next entry file descriptor
 */
static erom_filedescriptor_t *get_next_file_descriptor(erom_filedescriptor_t *fd)
{
	u32 next_entry_offset = get_val_from_hash0(read_le_u32((u8 *)&fd->next_fileoffset_hash));
	if (next_entry_offset)
		fd = (erom_filedescriptor_t *)(erom_info.start + next_entry_offset);
	else { /* no more files */
		return NULL;
	}

	return fd;
}

/*
 * function that get info about erom: start of 1st file descriptor, magic token, etc...
 */
static int get_erom_info(u8 *erom_start)
{
	register int32_t i;

	erom_info.start = NULL;

	for (i = 0; tokens[i] != NULL ; i++) {
		register u32 hash = get_string_hash(tokens[i]);

		u32 *p, *p2;
		for (p = (u32 *)erom_start, p2 = (u32 *)(erom_start + 1024); (uintptr_t)p < (uintptr_t)p2; p++) {

			if (read_le_u32((u8 *)p) == hash) {
				erom_info.start = (void *)erom_start;
				erom_info.fd = (erom_filedescriptor_t *)(erom_start  + ((uintptr_t)p - (uintptr_t)erom_start));
				erom_info.magic_token = (char *)tokens[i];

				return 1;
			}
		}
	}

	return 0;
}

/*
 * function that read and decrypt erom file
 */
int erom_readfile(u32 filename_hash, u8 *buf)
{
	register int32_t xor_size = 0; /* size in bytes of the xored datas */

	erom_filedescriptor_t *fd = get_file_descriptor_by_hash(filename_hash);
	if (!fd)
		return -1;

	register int32_t size = (int32_t)get_val_from_hash1(read_le_u32((u8 *)&fd->filesize_hash)) & 0x00ffffff;

	if (size < 0)
		return -2;

	if (size == 0)
		return 0;

	register u32 offset = get_val_from_hash0(read_le_u32((u8 *)&fd->fileoffset_hash));
	xor_size = get_val_from_hash0(read_le_u32((u8 *)&fd->xordata_size_hash));
	xor_size = xor_size << 2;

	register u32 fposition = 0;
	u8 *data = (u8 *)(erom_info.start + offset);
	u8 *xortable = (u8 *)(data - xor_size);

	if (fposition < xor_size) { /* if we are in a xored file section */
		xor_size -= fposition;
		if (size < xor_size)
			xor_size = size;

		/* printf("erom_readfile: size of xored data to read: %d bytes\n", xor_size); */

		/* transfer the file xortable data in the buffer, it will dexored below */
		memcpy(buf, (void *)(xortable + fposition), xor_size);

		u8 *p_buf = buf;
		u8 *p_xor = (u8 *)(data + fposition);			/* address where we must start to dexor with xortable */
		u8 *p_xor_end = (u8 *)(data + fposition + xor_size); 	/* address where we must stop to dexor */

		if (((uintptr_t)p_buf & 3) == ((uintptr_t)p_xor & 3)) {	/* if buf and xored data is on same alignment */
			while ((uintptr_t)p_buf & 3) { 		/* if unaligned on word boundary we dexor bytes */
				u8 *p = (u8 *)p_buf;
				u8 *p2 = (u8 *)p_xor;
				*p ^= *p2;
				p_xor++;
				p_buf++;
			}

			u32 *p = (u32 *)p_buf;
			u32 *p2 = (u32 *)p_xor;
			while ((uintptr_t)p2 < ((uintptr_t)p_xor_end & -4)) { /* if aligned on word boundary we dexor words */
				write_le_u32(read_le_u32((u8 *)p) ^ read_le_u32((u8 *)p2), (u8 *)p);
				p++;
				p2++;
			}
			p_xor = (u8 *)p2;
		}

		while ((uintptr_t)p_xor < (uintptr_t)p_xor_end) { /* dexor unaligned bytes remainder, if any */
			u8 *p = (u8 *)buf;
			u8 *p2 = (u8 *)p_xor;
			*p ^= *p2;
			p_xor++;
			buf++;
		}

		size -= xor_size;
		fposition += xor_size;
	}

	if (size >= 0) { /* copy datas, those are what still stored in clear */
		/* printf("erom_readfile: size of clear data to read: %d bytes\n", size); */

		memcpy((void *)(buf + xor_size), (void *)(data + fposition), size);
		fposition += size;
	}

	return size + xor_size;
}

/*
 *
 */
static void find_valid_filenames(char *hex_str)
{
	u32 hash = hexstring_to_hash(hex_str);
	printf("hash to find = 0x%08x\n", hash);

	char test_hash[16];
	int i, j, k, l, m, n, o;

	for (i = 0; i < 6; ++i) {
		strcat(test_hash, "\x30");
		for (j = 0x30; j < 0x5a; ++j) {
			test_hash[0] = j;
			if (test_hash[1] == 0) {
				if (get_string_hash(test_hash) == hash)
					printf("%s match!\n", test_hash);
				continue;
			}
			for (k = 0x30; k < 0x5a; ++k) {
				test_hash[1] = k;
				if (test_hash[2] == 0) {
					if (get_string_hash(test_hash) == hash)
						printf("%s match!\n", test_hash);
					continue;
				}
				for (l = 0x30; l < 0x5a; ++l) {
					test_hash[2] = l;
					if (test_hash[3] == 0) {
						if (get_string_hash(test_hash) == hash)
							printf("%s match!\n", test_hash);
						continue;
					}
					for (m = 0x30; m < 0x5a; ++m) {
						test_hash[3] = m;
						if (test_hash[4] == 0) {
							if (get_string_hash(test_hash) == hash)
								printf("%s match!\n", test_hash);	
							continue;
						}
						for (n = 0x30; n < 0x5a; ++n) {
							test_hash[4] = n;
							if (test_hash[5] == 0) {
								if (get_string_hash(test_hash) == hash)
									printf("%s match!\n", test_hash);
								continue;
							}
							for (o = 0x30; o < 0x5a; ++o) {
								test_hash[5] = o;
								if (get_string_hash(test_hash) == hash) {
									printf("%s match!\n", test_hash);
									continue;
								}
							}
						}
					}
				}
			}
		}		
	}
}

/*
 * print program usage
 */
static void print_usage(void)
{
	printf(PROGRAM_NAME " v" PROGRAM_VER " - " PROGRAM_DESC "\n");
	printf("usage: " PROGRAM_NAME " <command> <erom_dump_file>\n");
	printf("available commands are:\n");
	printf("\t-l, --list\n");
	printf("\t-x, --extract\n");
}

/*
 * main program function
 */
int main(int argc, char **argv)
{
	FILE *fh;
	int32_t r, command, fsize;
	u8 *buf;

	if (argc < 3) {
		printf("error: not enough arguments...\n");
		print_usage();
		return 0;
	}

	if ((!strcmp(argv[1], "-l")) || (!strcmp(argv[1], "--list")))
		command = CMD_LIST;
	else if ((!strcmp(argv[1], "-x")) || (!strcmp(argv[1], "--extract")))
		command = CMD_EXTRACT;
	else if ((!strcmp(argv[1], "-f")) || (!strcmp(argv[1], "--find-name-from-hash"))) {
		find_valid_filenames(argv[2]);
		return 0;
	}
	else {
		printf("error: invalid command...\n");
		print_usage();
		return 0;
	}

	fh = fopen(argv[2], "rb");
	if (fh) {
		fseek(fh, 0, SEEK_END);
		fsize = ftell(fh);
		if (!fsize) {
			fclose(fh);
			printf("error: input file '%s' is zero size...\n", argv[2]);
			return 0;
		}
			
		fseek(fh, 0, SEEK_SET);

		buf = malloc(fsize);
		if (!buf) {
			fclose(fh);
			printf("error: can't allocate memory...\n");
			return 0;
		}

		r = fread(buf, 1, fsize, fh);
		if (r != fsize) {
			fclose(fh);
			free(buf);
			printf("error: can't read input file '%s'\n", argv[2]);
			return 0;
		}

		fclose(fh);
	}
	else {
		printf("error: can't open input file '%s'\n", argv[2]);
		return 0;
	}

	if (!get_erom_info(buf)) {
		printf("error: can't get erom info, please check your erom dump integrity...\n");
		free(buf);
		return 0;
	}

	/* printf("erom_info.start=%08x erom_info.fd=%08x\n", (int)erom_info.start, (int)erom_info.fd); */

	erom_filedescriptor_t *fd = get_file_descriptor_by_name(erom_info.magic_token);
	if (!fd) {
		printf("error: failed to locate 1st file descriptor, please check your erom dump integrity...\n");
		free(buf);
		return 0;
	}

	register u32 erom_size = get_val_from_hash0(read_le_u32((u8 *)&fd->fileoffset_hash));
	printf("erom size (hex): 0x%08x magic_token: '%s'\n", (int)erom_size, erom_info.magic_token);

	register u32 filecount = get_val_from_hash1(read_le_u32((u8 *)&fd->filesize_hash)) & 0x00ffffff;
	printf("number of erom files: %d\n", (int32_t)filecount);

	while ((fd = get_next_file_descriptor(fd))) {
		char filename[64];

		register int i, found = 0;
		for (i=0; erom_known_filenames[i] != NULL; i++) {
			if (get_string_hash(erom_known_filenames[i]) == fd->filename_hash) {
				strcpy(filename, erom_known_filenames[i]);
				found = 1;
				break;
			}
		}

		if (!found)
			hash_to_hexstring(read_le_u32((u8 *)&fd->filename_hash), filename);

		register int32_t filesize = (int32_t)get_val_from_hash1(fd->filesize_hash) & 0x00ffffff;

		u8 *filebuf = malloc(filesize);
		if (!filebuf) {
			printf("error: can't allocate memory\n");
			free(buf);
			return 0;
		}

		/* read/decrypt file from erom into buffer */
		r = erom_readfile(read_le_u32((u8 *)&fd->filename_hash), filebuf);
		if (r != filesize) {
			printf("error: can't read/decrypt ouput file '%s'\n", filename);
			free(filebuf);
			free(buf);
			return 0;
		}

		int gzipped_file = 0;
		int32_t uncompressed_size = 0;
		if (((u8)filebuf[0] == 0x1f) && ((u8)filebuf[1] == 0x8b)) {
			gzipped_file = 1;
			uncompressed_size = read_le_u32((u8 *)&filebuf[filesize - 4]);
		}

		printf("%s - %d bytes", filename, filesize);
		if (gzipped_file)
			printf(" (gzip - uncompressed size: %d bytes)", uncompressed_size);
		printf("\n");

		if (command == CMD_EXTRACT) {
			if (gzipped_file)
				strcat(filename, ".gz");

			fh = fopen(filename, "wb");
			if (fh) {
				r = fwrite(filebuf, 1, filesize, fh);
				if (r != filesize) {
					printf("error: can't write ouput file '%s'\n", filename);
					fclose(fh);
					free(filebuf);
					free(buf);
					return 0;
				}
				fclose(fh);
			}
			else {
				printf("error: can't create ouput file '%s'\n", filename);
				free(filebuf);
				free(buf);
				return 0;
			}
		}

		free(filebuf);
	}

	free(buf);

	return 0;
}
