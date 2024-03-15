#include <stdio.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <cstdint>


#include "help.h"



#define APPENDIX_SIZE           12
#define BUFF_SIZE            2000000

#define MAX_KEY_LEN 16
#define NUM_ROUNDS 64



uint64_t fsize(const char* path);

int8_t CRC16_file(const char* path, uint8_t* dest);
void CRC16_frame(uint8_t* frame, uint32_t len, uint8_t* dest);

const uint8_t S_TABLE[256] =
{
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};
void vEncrypt (uint8_t* dest, uint8_t* data, uint64_t dataLen, uint8_t* key, uint8_t key_len);
void vDecrypt (uint8_t* dest, uint8_t* data, uint64_t dataLen, uint8_t* key, uint8_t key_len);


int main(int argc, char** argv)
{

    uint8_t     cmd_ok = 0;
    uint8_t     attach = 0;
    uint8_t     split = 0;


    const char*       sec_file_path = nullptr;
    const char*       container_file_path = nullptr;
    uint8_t           pwd[MAX_KEY_LEN];
    uint8_t           pwd_len;

    if ((argc == 2) and (!strcmp(argv[1],"-h")))
    {
        puts(HELP);
        return 0;
    }
    else if (argc > 2)
    {
        if ((argv[1][0] = '-') && (strlen (argv[1]) == 2))
        {
            pwd_len = ((strlen(argv[4]) == 8) || (strlen(argv[4]) == 16)) ? strlen(argv[4]) : 0;
            if (pwd_len)
            {
                memcpy(pwd, argv[4], pwd_len);
                container_file_path = argv[2];
                sec_file_path = argv[3];

                switch (argv[1][1])
                {
                case 'e' :
                    if (argc == 5)
                    {
                        attach = 1;
                        cmd_ok = 1;
                    }
                    break;
                case 's' :
                    if (argc == 5)
                    {
                        split = 1;
                        cmd_ok = 1;
                    }
                    break;
                }
            }
        }
    }

    if (!cmd_ok)
    {
        puts(PROMPT);
        return 0;
    }


    uint64_t    carrier_file_len = 0;
    uint64_t    sec_file_len = 0;
    uint64_t    container_file_len = 0;


    /**appendix sequence:
        2 bytes of CRC16(sec_file)
        8 bytes of carrier_file_len
        2 bytes of CRC16(prev not encrypted (!) 10 bytes)
        total: 12 bytes.
    */
    uint8_t    appendix[APPENDIX_SIZE];
    uint8_t*   cp_buff = nullptr;
    uint8_t*   sec_buff = nullptr;
    uint64_t pos;
    int32_t len;

    int32_t     sec_file, container_file;

    cp_buff = new uint8_t[BUFF_SIZE];
    sec_buff = new uint8_t[BUFF_SIZE];

    if (attach)
    {

        /*sec file*/
        sec_file_len = fsize(sec_file_path);

        sec_file = open (sec_file_path, O_RDONLY);
        if (sec_file < 1)
        {
            puts("err. sec_file open");
            return -1;
        }

        /*carrier file*/
        carrier_file_len = fsize(container_file_path);
        if (carrier_file_len < 1)
        {
            puts("err. carrier_file min len");
            return -1;
        }

        container_file = open (container_file_path, O_RDWR);
        if (container_file < 1)
        {
            puts("err. carrier_file as container open");
            return -1;
        }

        pos = 0;
        while (pos < sec_file_len)
        {
            lseek(sec_file, pos, SEEK_SET);
            len = read (sec_file, cp_buff, BUFF_SIZE);

            vEncrypt(sec_buff, cp_buff, ((len % 2) ? len - 1 : len), pwd, pwd_len);

            lseek(container_file, pos + carrier_file_len, SEEK_SET);

            if (len % 2)
            {
                if ((write(container_file, sec_buff, len - 1)) < len - 1)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }

                if ((write(container_file, cp_buff + len - 1, 1)) < 1)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }
            }
            else
            {
                if ((write(container_file, sec_buff, len)) < len)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }
            }

            pos += len;
        }

        close(sec_file);

        /*calc appendix*/
        CRC16_file(sec_file_path, appendix);
        memcpy(appendix + 2, (void*)&carrier_file_len, sizeof(uint64_t));
        CRC16_frame(appendix, APPENDIX_SIZE - 2, appendix + APPENDIX_SIZE - 2);

        /*encrypt appendix*/
        vEncrypt(sec_buff, appendix, APPENDIX_SIZE - 2, pwd, pwd_len);
        memcpy(appendix, sec_buff, APPENDIX_SIZE - 2);

        /*write appendix*/
        lseek(container_file, carrier_file_len + sec_file_len, SEEK_SET);
        if ((write(container_file, appendix, APPENDIX_SIZE)) < APPENDIX_SIZE)
        {
            puts("err. container_file appendix write");
            return -1;
        }


        close(container_file);
        unlink(sec_file_path);
    }

    if (split)
    {
        /*result file*/
        container_file_len = fsize(container_file_path);
        if (container_file_len < 1)
        {
            puts("err. container_file_len min len");
            return -1;
        }

        container_file = open (container_file_path, O_RDWR);
        if (container_file < 1)
        {
            puts("err. container_file_len open");
            return -1;
        }

        //read appendix
        lseek(container_file, container_file_len - APPENDIX_SIZE, SEEK_SET);
        if ((read (container_file, sec_buff, APPENDIX_SIZE)) != APPENDIX_SIZE)
        {
            puts("err. carrier_file read");
            return -1;
        };

        memcpy(appendix, sec_buff, APPENDIX_SIZE);
        //decrypt appendix
        vDecrypt(appendix, sec_buff, APPENDIX_SIZE - 2, pwd, pwd_len);


        //calc && check crc16 of 10 bytes
        CRC16_frame(appendix, APPENDIX_SIZE - 2, cp_buff);
        if (memcmp((appendix + APPENDIX_SIZE - 2), cp_buff, 2))
        {
            puts("Oops!");
            return -1;
        }

        carrier_file_len = *((uint64_t*)(appendix + 2));
        sec_file_len = container_file_len - carrier_file_len - APPENDIX_SIZE;

        uint32_t bytes_to_read;

        /*Write sec file*/

        sec_file = open (sec_file_path, O_RDWR | O_CREAT | O_TRUNC);
        if (sec_file < 1)
        {
            puts("err. sec_file open");
            return -1;
        }

        pos = carrier_file_len;

        while (pos < carrier_file_len + sec_file_len)
        {
            bytes_to_read = (pos + BUFF_SIZE <= carrier_file_len + sec_file_len) ? BUFF_SIZE : carrier_file_len + sec_file_len - pos;

            lseek(container_file, pos, SEEK_SET);
            len = read (container_file, sec_buff, bytes_to_read);

            vDecrypt(cp_buff, sec_buff, ((len % 2) ? len - 1 : len), pwd, pwd_len);

            lseek(sec_file, pos - carrier_file_len, SEEK_SET);

            if (len % 2)
            {
                if ((write(sec_file, cp_buff, len - 1)) < len - 1)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }

                if ((write(sec_file, sec_buff + len - 1, 1)) < 1)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }
            }
            else
            {
                if ((write(sec_file, cp_buff, len)) < len)
                {
                    puts("err. container_file sec_file write");
                    return -1;
                }
            }

            pos += len;
        }

        close(sec_file);

        //check CRC16
        CRC16_file(sec_file_path, cp_buff);
        if (memcmp(cp_buff, appendix, 2))
        {
            puts("err. sec_file CRC16");
//            unlink(argv[2]);
//            return -1;
        }

        //cut secret file and appendix
        ftruncate(container_file, carrier_file_len);
        close(container_file);
    }


    delete []cp_buff;
    delete []sec_buff;
    return 0;
}


uint64_t fsize (const char* path)
{
    struct stat finfo;
    if (!stat(path, &finfo)) return (uint64_t)finfo.st_size;
    return -1;
};
void CRC16_frame(uint8_t* frame, uint32_t len, uint8_t* dest)
{
    uint16_t crcReg = 0xFFFF;
    for (uint32_t i = 0; i < len; i++)
    {
        crcReg ^= * frame;
        for (uint8_t j = 0; j < 8; j++)
        {
            if (crcReg & 0x01)
            {
                crcReg >>= 1;
                crcReg ^= 0xA001;
            }
            else crcReg >>= 1;
        }
        frame ++;
    }
    * dest = crcReg & 0x00FF;
    * (dest + 1) = crcReg >> 8;
};
int8_t CRC16_file(const char* path, uint8_t* dest)
{
    uint64_t file_size, offset;
    uint8_t* frame;
    uint32_t len, frame_size;
    int32_t fd;
    uint16_t crcReg;


    struct stat finfo;
    if (!stat(path, &finfo)) file_size = (uint64_t)finfo.st_size;
    else return -1;


    fd = open (path, O_RDONLY);
    if (fd < 0) return -1;

    frame_size = 1000000;
    frame = new uint8_t[frame_size];
    offset = 0;


    crcReg = 0xFFFF;

    while (offset < file_size)
    {
        lseek(fd, offset, SEEK_SET);
        len = read(fd, frame, frame_size);

        for (uint32_t i = 0; i < len; i++)
        {
            crcReg ^= frame[i];
            for (uint16_t j = 0; j < 8; j++)
            {
                if (crcReg & 0x01)
                {
                    crcReg >>= 1;
                    crcReg ^= 0xA001;
                }
                else crcReg >>= 1;
            }
        }

        offset += frame_size;
    }

    * dest = crcReg & 0x00FF;
    * (dest + 1) = crcReg >> 8;
    delete []frame;
    return 0;
};
void vEncrypt (uint8_t* dest, uint8_t* data, uint64_t dataLen, uint8_t* key, uint8_t key_len)
{
    uint8_t numBits = 3;
    int currKeyPos = 0;
    uint8_t lBlock = 0;
    uint8_t rBlock = 0;
    uint8_t bBlock = 0;
    uint8_t overflowBits = 0;

    for (uint64_t i = 0; i < dataLen - 1; i+=2)
    {
        lBlock = data[i];
        rBlock = data[i + 1];

        for (int r = 0; r < NUM_ROUNDS; r++)
        {
            bBlock = S_TABLE[rBlock];
            bBlock = (bBlock ^ key[currKeyPos]);
            if (currKeyPos == key_len - 1) currKeyPos = 0;
            else currKeyPos++;

            overflowBits = (bBlock) >> (8 - numBits);
            bBlock =  (bBlock << numBits) |  overflowBits;
            bBlock = bBlock ^ lBlock;
            if (r == NUM_ROUNDS - 1)
            {
                dest[i] = bBlock;
                dest[i + 1] = rBlock;
            }
            else
            {
                lBlock = rBlock;
                rBlock = bBlock;
            }
        }
    }
    return;
};
void vDecrypt (uint8_t* dest, uint8_t* data, uint64_t dataLen, uint8_t* key, uint8_t key_len)
{
    uint8_t numBits = 3;
    int currKeyPos = key_len -1;
    uint8_t lBlock = 0;
    uint8_t rBlock = 0;
    uint8_t bBlock = 0;
    uint8_t overflowBits = 0;

    for (uint64_t i = 0; i < dataLen; i+=2)
    {
        lBlock = data[i];
        rBlock = data[i + 1];

        for (int r = 0; r < NUM_ROUNDS; r++)
        {
            bBlock = S_TABLE[rBlock];
            bBlock = (bBlock ^ key[currKeyPos]);
            if (currKeyPos == 0) currKeyPos = key_len - 1;
            else currKeyPos--;

            overflowBits = (bBlock) >> (8 - numBits);
            bBlock =  (bBlock << numBits) |  overflowBits;
            bBlock = bBlock ^ lBlock;
            if (r == NUM_ROUNDS - 1)
            {
                dest[i] = bBlock;
                if (i == dataLen - 1) break;
                dest[i + 1] = rBlock;
            }
            else
            {
                lBlock = rBlock;
                rBlock = bBlock;
            }
        }
    }
    return;
};

