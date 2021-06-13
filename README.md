# soal-shift-sisop-modul-4-IT14-2021

Repository Sebagai Laporan Resmi Soal Shift Modul 3 Praktikum Sistem Operasi 2021
Disusun oleh :

- Romandhika Rijal I (0531180000048)
- Moch. Shaladin Rangga (05311940000029)
- Moh. Ibadul Haqqi (05311940000037)

---

## soal 1
  Di suatu jurusan, terdapat admin lab baru yang super duper gabut, ia bernama Sin. Sin baru menjadi admin di lab tersebut selama 1 bulan. Selama sebulan tersebut ia bertemu orang-orang hebat di lab tersebut, salah satunya yaitu Sei. Sei dan Sin akhirnya berteman baik. Karena belakangan ini sedang ramai tentang kasus keamanan data, mereka berniat membuat filesystem dengan metode encode yang mutakhir. Berikut adalah filesystem rancangan Sin dan Sei :

NOTE : 
```
Semua file yang berada pada direktori harus ter-encode menggunakan Atbash cipher(mirror).
Misalkan terdapat file bernama kucinglucu123.jpg pada direktori DATA_PENTING
“AtoZ_folder/DATA_PENTING/kucinglucu123.jpg” → “AtoZ_folder/WZGZ_KVMGRMT/pfxrmtofxf123.jpg”
Note : filesystem berfungsi normal layaknya linux pada umumnya, Mount source (root) filesystem adalah directory /home/[USER]/Downloads, dalam penamaan file ‘/’ diabaikan, dan ekstensi tidak perlu di-encode.
Referensi : https://www.dcode.fr/atbash-cipher
```

a). Jika sebuah direktori dibuat dengan awalan “AtoZ_”, maka direktori tersebut akan menjadi direktori ter-encode

b). Jika sebuah direktori di-rename dengan awalan “AtoZ_”, maka direktori tersebut akan menjadi direktori ter-encode

c). Apabila direktori yang terenkripsi di-rename menjadi tidak ter-encode, maka isi direktori tersebut akan terdecode

d). Setiap pembuatan direktori ter-encode (mkdir atau rename) akan tercatat ke sebuah log. `Format : /home/[USER]/Downloads/[Nama Direktori] → /home/[USER]/Downloads/AtoZ_[Nama Direktori]`

e). Metode encode pada suatu direktori juga berlaku terhadap direktori yang ada di dalamnya.(rekursif)

## Penyelesaian
### Code:

```c
void atbash(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    char *dot = strrchr(name, '.');
    char *atoz = strstr(name, "AtoZ_");
    int i;
    for (i = atoz - name; i < strlen(name); ++i) {
        if (name[i] == '/') {
            break;
        }
    }

    if (atoz == NULL) {
        i = 0;
    }

    int last = dot ? dot - name: strlen(name);
    for (; i < last; ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 155 - name[i];
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 219 - name[i];
        }
    }
}

void rot13(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int name_len = strlen(name);
    for (int i = 0; i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }

    char *dot = strrchr(name, '.');
    for (int i = (int)(dot - name); i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }
}

void vigenere_enc(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] + key[n] - 130) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] + key[n] - 162) % 26;
            n = (n + 1) % 5;
        }
    }
}

void vigenere_dec(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] - key[n] + 26) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] - key[n] - 6) % 26;
            n = (n + 1) % 5;
        }
    }

}

void check_encryption(char *path, const char *fpath) {
    printf("check %s %s\n", path, fpath);
    if (strstr(fpath, "/AtoZ_") != NULL) {
        atbash(path);
    } else if (strstr(fpath, "/RX_") != NULL) {
        atbash(path);
        rot13(path);
    }
    printf("enc %s\n", path);
}


static int xmp_getattr(const char *path, struct stat *st) {
    char fpath[2000], name[1000], temp[1000];
    sprintf(temp, "%s", path);

    int name_len = strlen(path);
    for (int i = 0; i < name_len; i++) {
        name[i] = path[i + 1];
    }
    printf("getattr %s\n", name);
    
    // vigenere_dec(name);
    // atbash(name);
    // rot13(name);
    check_encryption(temp, path);
    sprintf(fpath, "%s/%s", dirpath, temp);
    
    int res = lstat(fpath, st);
    if (res != 0){
        return -ENOENT;
    }

    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    int res;
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } 
    else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("readdir: %s\n", fpath);

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        char fullpathname[2257];
        sprintf(fullpathname, "%s/%s", fpath, de->d_name);
        
        char temp[1000];
        strcpy(temp, de->d_name);
        // vigenere_enc(temp);
        // atbash(name);
        // rot13(name);
        check_encryption(temp, fpath);

        res = (filler(buf, temp, &st, 0));
        if (res != 0) break;
    }

    closedir(dp);

    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);

        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("read %s\n", fpath);
    
    int res = 0;
    int fd = 0 ;

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int xmp_rename(const char *old, const char *new) {
    char fpath[2000];
    char name[1000];
    char new_name[1000];
    createlogrename(old, new);
    if (strcmp(old, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", old);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, fpath);

        memset(fpath, 0, sizeof(fpath));
        memset(new_name, 0, sizeof(new_name));

        sprintf(fpath, "%s/%s", dirpath, name);
        sprintf(new_name, "%s/%s", dirpath, new);
    }

    printf("rename %s %s\n", fpath, new_name);

    int res = rename(fpath, new_name);
    if (res == -1) 
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    printf("mkdir %s\n", path);
    createlog("mkdir", path);
    char fpath[2000];
    
    sprintf(fpath, "%s/%s", dirpath, path);
    mkdir(fpath, mode);

    return 0;
}

static int xmp_rmdir(const char *path) {
    printf("rmdir %s\n", path);
    createlog("rmdir", path);
    char fpath[2000];

    sprintf(fpath, "%s/%s", dirpath, path);
    int res = rmdir(fpath);
    if (res != 0) return -errno;

    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .readdir    = xmp_readdir,
    .read       = xmp_read,
    .rename     = xmp_rename,
    .mkdir      = xmp_mkdir,
    .rmdir      = xmp_rmdir,
};

int main(int argc, char *argv[]) {
    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}

```

## Penjelasan Code
1. pertama kami membuat fungsi `atbash` untuk mengenkripsi direktori yang memiliki awalan `AtoZ_`. Metode `atbash` sendiri adalah suatu teknik enkripsi, yang dimana huruf alphabet diganti dengan kebalikan dari abjadnya. Sehingga jika nanti terdapat direktori yang dibuat/direname dengan nama `AtoZ_`, maka isi dari direktori itu akan terenkripsi.

```c
void atbash(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    char *dot = strrchr(name, '.');
    char *atoz = strstr(name, "AtoZ_");
    int i;
    for (i = atoz - name; i < strlen(name); ++i) {
        if (name[i] == '/') {
            break;
        }
    }

    if (atoz == NULL) {
        i = 0;
    }

    int last = dot ? dot - name: strlen(name);
    for (; i < last; ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 155 - name[i];
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 219 - name[i];
        }
    }
}

```
2. Selanjutnya kami membuat fungsi dimana untuk cek enkripsi, yang berfungsi untuk mengecek apakah direktori yang diinputkan terdapat nama `AtoZ_` atau `RX_.` Jika direktorinya terdapat nama `AtoZ_` maka fungsi enkripsi atbash akan diterapkan pada direktpri tersebut. Dan jika terdapat `RX_` maka fungsi enkripsi rot13 dan atbash akan diterapkan pada direktori tersebut.

```c
void check_encryption(char *path, const char *fpath) {
    printf("check %s %s\n", path, fpath);
    if (strstr(fpath, "/AtoZ_") != NULL) {
        atbash(path);
    } else if (strstr(fpath, "/RX_") != NULL) {
        atbash(path);
        rot13(path);
    }
    printf("enc %s\n", path);
}

```
3. Untuk menjalankan fungsi yang bisa berjalan terutama fungsi listingnya kita perlu mendefinisikan fuse operations `getatt` untuk mendapatkan attribut dalam sebuah direktori, attribut sendiri adalah detail detail dari apapun dalam direktori. Jika fungsi getattr tidak didefinisikan maka fungsi fuse tidak akan bisa berjalan.

```c
static int xmp_getattr(const char *path, struct stat *st) {
    char fpath[2000], name[1000], temp[1000];
    sprintf(temp, "%s", path);

    int name_len = strlen(path);
    for (int i = 0; i < name_len; i++) {
        name[i] = path[i + 1];
    }
    printf("getattr %s\n", name);
    
    // vigenere_dec(name);
    // atbash(name);
    // rot13(name);
    check_encryption(temp, path);
    sprintf(fpath, "%s/%s", dirpath, temp);
    
    int res = lstat(fpath, st);
    if (res != 0){
        return -ENOENT;
    }

    return 0;
}

```
4. selanjutnya kami disini membuat fungsi `readdir` yang digunakan untuk membaca direktori yang diminta. Fungsi ini juga menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi

```c
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    int res;
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } 
    else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("readdir: %s\n", fpath);

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        char fullpathname[2257];
        sprintf(fullpathname, "%s/%s", fpath, de->d_name);
        
        char temp[1000];
        strcpy(temp, de->d_name);
        // vigenere_enc(temp);
        // atbash(name);
        // rot13(name);
        check_encryption(temp, fpath);

        res = (filler(buf, temp, &st, 0));
        if (res != 0) break;
    }

    closedir(dp);

    return 0;
}

```
5. lalu kami membuat fungsi `read` yang digunakan untuk mendapat data dari file yang dibuka. Fungsi ini untuk menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi

```c
static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", path);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);

        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("read %s\n", fpath);
    
    int res = 0;
    int fd = 0 ;

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

```
6. lalu kami membuat fungsi `rename` yang digunakan untuk merename folder sebelumnya menjadi nama folder yang diinginkan. Fungsi ini juga untuk menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi. Selain itu, fungsi ini juga akan menambahkan fungsi `createlogrename` untuk dicatat dalam log. Fungsi ini akan dijelaskan lebih lanjut di no.4

```c
static int xmp_rename(const char *old, const char *new) {
    char fpath[2000];
    char name[1000];
    char new_name[1000];
    createlogrename(old, new);
    if (strcmp(old, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", old);
        // vigenere_dec(name);
        // atbash(name);
        // rot13(name);
        check_encryption(name, fpath);

        memset(fpath, 0, sizeof(fpath));
        memset(new_name, 0, sizeof(new_name));

        sprintf(fpath, "%s/%s", dirpath, name);
        sprintf(new_name, "%s/%s", dirpath, new);
    }

    printf("rename %s %s\n", fpath, new_name);

    int res = rename(fpath, new_name);
    if (res == -1) 
        return -errno;

    return 0;
}

```
7. Lalu kami membuat fungsi `mkdir`. Fungsi ini digunakan untuk membuat folder yang diinginkan. kemudian aktifitas ini akan dicatat dalam log dengan fungsi `createlog` yang akan dijelaskan lebih lanjut di no.4.

```c
static int xmp_mkdir(const char *path, mode_t mode) {
    printf("mkdir %s\n", path);
    createlog("mkdir", path);
    char fpath[2000];
    
    sprintf(fpath, "%s/%s", dirpath, path);
    mkdir(fpath, mode);

    return 0;
}

```
Kami juga membuat fungsi `rmdir` untuk menghapus direktori. kemudian aktifitas ini dicatat dalam log dengan fungsi `createlog` yang akan dijelaskan lebih lanjut di no.4

```c
static int xmp_rmdir(const char *path) {
    printf("rmdir %s\n", path);
    createlog("rmdir", path);
    char fpath[2000];

    sprintf(fpath, "%s/%s", dirpath, path);
    int res = rmdir(fpath);
    if (res != 0) return -errno;

    return 0;
}

```

### Kendala yang dihadapi
Masih belum mengerti tentang struct struct pada fuse dan belum paham cara memodifikasinya



## soal 2
Selain itu Sei mengusulkan untuk membuat metode enkripsi tambahan agar data pada komputer mereka semakin aman. Berikut rancangan metode enkripsi tambahan yang dirancang oleh Sei
a). Jika sebuah direktori dibuat dengan awalan “RX_[Nama]”, maka direktori tersebut akan menjadi direktori terencode beserta isinya dengan perubahan nama isi sesuai kasus nomor 1 dengan algoritma tambahan ROT13 (Atbash + ROT13).

b). Jika sebuah direktori di-rename dengan awalan “RX_[Nama]”, maka direktori tersebut akan menjadi direktori terencode beserta isinya dengan perubahan nama isi sesuai dengan kasus nomor 1 dengan algoritma tambahan Vigenere Cipher dengan key “SISOP” (Case-sensitive, Atbash + Vigenere).

c). Apabila direktori yang terencode di-rename (Dihilangkan “RX_” nya), maka folder menjadi tidak terencode dan isi direktori tersebut akan terdecode berdasar nama aslinya.

d). Setiap pembuatan direktori terencode (mkdir atau rename) akan tercatat ke sebuah log file beserta methodnya (apakah itu mkdir atau rename).

e). Pada metode enkripsi ini, file-file pada direktori asli akan menjadi terpecah menjadi file-file kecil sebesar 1024 bytes, sementara jika diakses melalui filesystem rancangan Sin dan Sei akan menjadi normal. Sebagai contoh, Suatu_File.txt berukuran 3 kiloBytes pada directory asli akan menjadi 3 file kecil yakni:

```
Suatu_File.txt.0000
Suatu_File.txt.0001
Suatu_File.txt.0002
```

Ketika diakses melalui filesystem hanya akan muncul Suatu_File.txt

## Penyelesaian

### Code

```c
void rot13(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int name_len = strlen(name);
    for (int i = 0; i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }

    char *dot = strrchr(name, '.');
    for (int i = (int)(dot - name); i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }
}

void vigenere_enc(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] + key[n] - 130) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] + key[n] - 162) % 26;
            n = (n + 1) % 5;
        }
    }
}

void vigenere_dec(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] - key[n] + 26) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] - key[n] - 6) % 26;
            n = (n + 1) % 5;
        }
    }

}

void check_encryption(char *path, const char *fpath) {
    printf("check %s %s\n", path, fpath);
    if (strstr(fpath, "/AtoZ_") != NULL) {
        atbash(path);
    } else if (strstr(fpath, "/RX_") != NULL) {
        atbash(path);
        rot13(path);
    }
    printf("enc %s\n", path);
}

```
### Penjelasan code

1. Kami membuat fungsi `rot13` agar setiap direktori yang dibuat yang diwali `“RX_[Nama]”`, maka isi dari direktori akan terencode dengan algoritma tambahan `ROT13 (Atbash + ROT13)`

```c
void rot13(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int name_len = strlen(name);
    for (int i = 0; i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }

    char *dot = strrchr(name, '.');
    for (int i = (int)(dot - name); i < name_len; ++i) {
        if ('A' <= name[i] && name[i] <= 'M') {
            name[i] = 13 + name[i];
        } else if ('N' <= name[i] && name[i] <= 'Z') {
            name[i] = -13 + name[i];
        } else if ('a' <= name[i] && name[i] <= 'm') {
            name[i] = 13 + name[i];
        } else if ('n' <= name[i] && name[i] <= 'z') {
            name[i] = -13 + name[i];
        }
    }
}

```

2. kemudian kami buat fungsi `vigenere_en`c untuk mengenkripsi isi dari direktori yang direname dengan awalan `“RX_[Nama]”` menggunakan algoritma tambahan Vigenere Cipher dengan key `“SISOP” (Case-sensitive, Atbash + Vigenere)`

```c
void vigenere_enc(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] + key[n] - 130) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] + key[n] - 162) % 26;
            n = (n + 1) % 5;
        }
    }
}

```

3. Lalu kami membuat fungsi `vignere_dec` untuk mendekripsi direktori yang direname menjadi tanpa `“RX_”`. Maka isi direktori akan terdecode

```c
void vigenere_dec(char *name) {
    char *key = "SISOP";

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    int n = 0;

    char *dot = strrchr(name, '.');
    for (int i = 0; i < (int)(dot - name); ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 65 + (name[i] - key[n] + 26) % 26;
            n = (n + 1) % 5;
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 97 + (name[i] - key[n] - 6) % 26;
            n = (n + 1) % 5;
        }
    }

}

```


### Kendala yang dihadapi
kelompok kami tidak dapat menyelesaikan nomor 2d dan e dikarenakan kami belum dapat memahami cara untuk menyelesaikan soal tersebut. sehingga kelompok kami hanya dapat mengerjakan 2a, b, c saja. dan kami Masih belum mengerti tentang struct struct pada fuse dan belum paham cara memodifikasinya


# soal 3
Karena Sin masih super duper gabut akhirnya dia menambahkan sebuah fitur lagi pada filesystem mereka.
a). Jika sebuah direktori dibuat dengan awalan “A_is_a_”, maka direktori tersebut akan menjadi sebuah direktori spesial

b). Jika sebuah direktori di-rename dengan memberi awalan “A_is_a_”, maka direktori tersebut akan menjadi sebuah direktori spesial

c). Apabila direktori yang terenkripsi di-rename dengan menghapus “A_is_a_” pada bagian awal nama folder maka direktori tersebut menjadi direktori normal

d). Direktori spesial adalah direktori yang mengembalikan enkripsi/encoding pada direktori “AtoZ_” maupun “RX_” namun masing-masing aturan mereka tetap berjalan pada direktori di dalamnya (sifat recursive  “AtoZ_” dan “RX_” tetap berjalan pada subdirektori).

e). Pada direktori spesial semua nama file (tidak termasuk ekstensi) pada fuse akan berubah menjadi lowercase insensitive dan diberi ekstensi baru berupa nilai desimal dari binner perbedaan namanya.

Contohnya jika pada direktori asli nama filenya adalah “FiLe_CoNtoH.txt” maka pada fuse akan menjadi “file_contoh.txt.1321”. 1321 berasal dari biner 10100101001.

### Penyelesaian
<img src=https://github.com/Bhaskaraa/SoalShiftSISOP20_modul4_T02/blob/master/Screenshot/S__11214850.jpg>


# soal 4
Untuk memudahkan dalam memonitor kegiatan pada filesystem mereka Sin dan Sei membuat sebuah log system dengan spesifikasi sebagai berikut.
a). Log system yang akan terbentuk bernama “SinSeiFS.log” pada direktori home pengguna (/home/[user]/SinSeiFS.log). Log system ini akan menyimpan daftar perintah system call yang telah dijalankan pada filesystem.

b). Karena Sin dan Sei suka kerapian maka log yang dibuat akan dibagi menjadi dua level, yaitu INFO dan WARNING.

c). Untuk log level WARNING, digunakan untuk mencatat syscall rmdir dan unlink

d). Sisanya, akan dicatat pada level INFO

e). Format untuk logging yaitu:

`[Level]::[dd][mm][yyyy]-[HH]:[MM]:[SS]:[CMD]::[DESC :: DESC]`

Level : Level logging, dd : 2 digit tanggal, mm : 2 digit bulan, yyyy : 4 digit tahun, HH : 2 digit jam (format 24 Jam),MM : 2 digit menit, SS : 2 digit detik, CMD : System Call yang terpanggil, DESC : informasi dan parameter tambahan

INFO::28052021-10:00:00:CREATE::/test.txt

INFO::28052021-10:01:00:RENAME::/test.txt::/rename.txt

## Penyelesaian
### Code

```c
// Fungsi untuk membuat log
void createlog(const char process[100], const char fpath[1000]) {
    char text[2000];
    FILE *fp = fopen("/home/shaladin/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    if (strcmp(process, "unlink") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::UNLINK::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "mkdir") == 0) {
        sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::MKDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "rmdir") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::RMDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose (fp);
}

// Fungsi untuk membuat log khusus proses rename
void createlogrename(const char from[1000], const char to[1000]) {
    FILE *fp = fopen("/home/shaladin/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char text[2000];

    sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::RENAME::%s::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, from, to);
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose(fp);
}

```

### Penjelasan Code

1. Kami membuat fungsi `createlog` yang berfungsi untuk mencatat proses yang telah dilakukan user sebelumnya, seperti membuat atau menghapus direktori. dan disini kami membedakan levelnya. Ada level `info` dan `warning`. pada level `info` digunakan untuk mencatat `syscall` `rmdir` dan `unlink`. Sedangkan untuk level `info` untuk `syscall` yang lainnya.

```c
// Fungsi untuk membuat log
void createlog(const char process[100], const char fpath[1000]) {
    char text[2000];
    FILE *fp = fopen("/home/shaladin/modul 4/SinSeiFS.log","a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    if (strcmp(process, "unlink") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::UNLINK::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "mkdir") == 0) {
        sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::MKDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "rmdir") == 0) {
        sprintf(text, "WARNING::%02d%02d%04d-%02d:%02d:%02d::RMDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose (fp);
}

```

2. Lalu kami membuat fungsi `createlogrename` untuk proses rename log

```c
// Fungsi untuk membuat log khusus proses rename
void createlogrename(const char from[1000], const char to[1000]) {
    FILE *fp = fopen("/home/shaladin/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char text[2000];

    sprintf(text, "INFO::%02d%02d%04d-%02d:%02d:%02d::RENAME::%s::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, from, to);
    for (int i = 0; text[i] != '\0'; i++) {
            fputc(text[i], fp);
    }
    fclose(fp);
}

```
3. fungsi `createlog` dan `createlogrename` ini akan ditambahkan ke setiap fungsi `syscall` yang dibuat sebelumnya. Agar semua `syscall` yang dilakukan oleh user dicatat dalam log yang sudah ditentukan sebelumnya.


# Dokumentasi
1. untuk eksekusi program
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853631510706782228/unknown.png>

2. untuk membuat folder yang belum terenkripsi
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853631723014455336/unknown.png>
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853631795405127720/unknown.png>

3. mengganti folder dengan nama AtoZ_
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853631993144410122/unknown.png>

4. folder data_penting terenkripsi
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853632078187855952/unknown.png>

5. mengubah folder AtoZ_ menjadi folder baru dan folder tersebut ke decrypt
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853632304290070569/unknown.png>

6. sinseifs.log
<img src=https://cdn.discordapp.com/attachments/841192613917884436/853632540483780638/unknown.png>
