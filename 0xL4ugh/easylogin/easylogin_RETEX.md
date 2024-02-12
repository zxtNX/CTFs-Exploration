---
title: "L4ugh CTF 2024 : easylogin"
tags:
  - CTF
  - L4UGH
  - RETEX
  - REVERSE-ENGINEERING
---
# Description du challenge

Dans ce challenge, on nous donne deux fichiers soit "easylogin" et "token_validation". A première vue, au nom de ces fichiers, on peut penser que easylogin serait le fichier où se trouverait notre mot de passe car ça serait le fichier gérant le "login" et token_validation serait le fichier permettant de valider un token.

# Reconnaissance

**Avant toute chose, c'est toujours sympa de faire un file sur ces deux fichiers :**

```
> file easylogin 
easylogin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f6622ff5ad3130f6b25ad0aa0904b16aaa2bf5ee, for GNU/Linux 3.2.0, stripped
```

```
> file token_validation 
token_validation: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9bfc638f3117fe16f6c294dcb1a54f04111fb935, for GNU/Linux 3.2.0, stripped
```

Bon, les fichiers ont l'air d'être similaire sur les particularités définies via l'utilitaire file.

Etant donné que le challenge nous demande de trouver un mot de passe car on nous a dit que le flag ressemble à 0xL4ugH{password}, je vais d'abord m'attaquer au fichier easylogin.

**On effectue d'abord un strings pour récolter d'autres informations de reconnaissances qui pourraient nous être essentielles pour nos analyses futures :** 

```c
> strings easylogin
/lib64/ld-linux-x86-64.so.2
strcpy
puts
free
strlen
malloc
__libc_start_main
__cxa_finalize
printf
__isoc99_scanf
strcmp
libc.so.6
GLIBC_2.7
GLIBC_2.34
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
ABCDEFGHH
IJKLMNOPH
QRSTUVWXH
YZabcdefH
ghijklmnH
opqrstuvH
wxyz0123H
456789+/H
VUUUH
VUUUH
pDG/SbSeH
hGM2l16sH
RzFmxRDZH
NCti2PNXH
zY9ZH
Enter username: 
Enter password: 
Enter token: 
Login successful!
Flag is 0xl4ugh{password}
Login failed. Incorrect username or password.
;*3$"
GCC: (Debian 13.2.0-10) 13.2.0
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

On voit déjà certaines choses intéressantes à noter. On peut déjà supposer qu'une comparaison est effectuée grâce au strcmp et qu'il y a strlen qui pourrait nous faire supposer qu'un système est mis en place pour peut-être modifier une chaîne ou alors ça peut également être quelque chose de trivial qui n'a rien à voir. Enfin, on a diverses chaînes de caractères qui sont print via printf comme "Enter token" ou "Enter password".

Parmi toutes ces chaînes, une séquence m'intrigue fortement car différente des autres :
```c
pDG/SbSeH
hGM2l16sH
RzFmxRDZH
NCti2PNXH
zY9ZH
```

Je la conserve de côté, sait-on jamais.

Maintenant, je me suis dit que j'aimerais bien voir comment fonctionne le programme dynamiquement, donc j'effectue une analyse dynamique via GDB.

**Mais avant ça je vérifie s'il existe de potentielles protections mises en place sur le fichier grâce à pwntools :**

```c
pwn checksec easylogin 
[*] '/home/rabbit/Documents/Workspace/Projects/CTF/laught/easy_login/easylogin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Ensuite je lance le programme avec gdb :**

J'essaie de mettre un breakpoint sur main de manière explicite via la commande `b main` mais comme je m'en doutais ce n'est pas possible, cette fonction n'est pas définie selon gdb.
De ce fait j'effectue un `i files` car pour les binaires PIE, on peut souvent trouver l'adresse de l'entrée principale du programme en consultant l'adresse d'entrée du programme (`_start`) :

```c
Local exec file:
	`/home/rabbit/Documents/Workspace/Projects/CTF/laught/easy_login/easylogin', file type elf64-x86-64.
	Entry point: 0x10c0
	0x0000000000000318 - 0x0000000000000334 is .interp
	0x0000000000000338 - 0x0000000000000358 is .note.gnu.property
	0x0000000000000358 - 0x000000000000037c is .note.gnu.build-id
	0x000000000000037c - 0x000000000000039c is .note.ABI-tag
	0x00000000000003a0 - 0x00000000000003c4 is .gnu.hash
	0x00000000000003c8 - 0x0000000000000518 is .dynsym
	0x0000000000000518 - 0x00000000000005e6 is .dynstr
	0x00000000000005e6 - 0x0000000000000602 is .gnu.version
	0x0000000000000608 - 0x0000000000000648 is .gnu.version_r
	0x0000000000000648 - 0x0000000000000708 is .rela.dyn
	0x0000000000000708 - 0x00000000000007c8 is .rela.plt
	0x0000000000001000 - 0x0000000000001017 is .init
	0x0000000000001020 - 0x00000000000010b0 is .plt
	0x00000000000010b0 - 0x00000000000010b8 is .plt.got
	0x00000000000010c0 - 0x00000000000018fb is .text
	0x00000000000018fc - 0x0000000000001905 is .fini
	0x0000000000002000 - 0x000000000000209e is .rodata
	0x00000000000020a0 - 0x00000000000020ec is .eh_frame_hdr
	0x00000000000020f0 - 0x0000000000002220 is .eh_frame
	0x0000000000003dd0 - 0x0000000000003dd8 is .init_array
	0x0000000000003dd8 - 0x0000000000003de0 is .fini_array
	0x0000000000003de0 - 0x0000000000003fc0 is .dynamic
	0x0000000000003fc0 - 0x0000000000003fe8 is .got
	0x0000000000003fe8 - 0x0000000000004040 is .got.plt
	0x0000000000004040 - 0x0000000000004050 is .data
	0x0000000000004050 - 0x0000000000004058 is .bss
```

Ok super, maintenant on sait que  `_start` commence ici : `Entry point: 0x10c0`

Maintenant, je rappelle que comme c'est un PIE, on ne pourra certainement pas mettre un breakpoint sur cette adresse, qui est une adresse relative qui doit donc être ajustée pour obtenir l'adresse réelle à laquelle le code sera chargé en mémoire. Car les adresses mémoire ne sont pas fixes et peuvent changer à chaque exécution quand PIE est activé.

**Afin donc de trouver un moyen de placer notre point d'arrêt sur main on a plusieurs options qui s'offrent à nous :**
- Utiliser la valeur `0x555555554000` qui est une adresse de base typique pour le chargement de PIEs lors de l'exécution sous GDB, mais elle peut varier. On setterait le breakpoint comme ça : `b *0x555555554000+0x10c0` et on tenterait par la suite de trouver main.
- Si cette adresse ne fonctionne pas, on peut aussi tout simplement faire un `i fun main` pour afficher toutes les fonctions correspondant à la regex "main" et ainsi potentiellement trouver `__libc_start_main`.
- Si aucune de ces méthodes fonctionnent, on peut essayer d'exécuter le programme en s'arrêtant sur la première instruction grâce à `starti` et utiliser la commande `vmmap` ou`info proc mappings` pour tenter de trouver des adresses sur lesquelles on pourrait s'arrêter afin de plus tard trouver la fonction main.

Pour ma part j'ai utilisé la seconde méthode qui m'a directement montré l'existence de `__libc_start_main`.
Cette fonction me permettra de trouver main, car en règle générale cette fonction prend en argument (souvent `rdi`) l'adresse vers main.
Je fais donc un disas de cette fonction afin de trouver l'endroit où main serait utilisée :

```c
disass __libc_start_main
Dump of assembler code for function __libc_start_main:
=> 0x00007ffff7dd8d00 <+0>:	endbr64
   0x00007ffff7dd8d04 <+4>:	push   r15
   0x00007ffff7dd8d06 <+6>:	push   r14
   0x00007ffff7dd8d08 <+8>:	mov    r14,rcx
   0x00007ffff7dd8d0b <+11>:	push   r13
   0x00007ffff7dd8d0d <+13>:	push   r12
   0x00007ffff7dd8d0f <+15>:	push   rbp
   0x00007ffff7dd8d10 <+16>:	mov    ebp,esi
   0x00007ffff7dd8d12 <+18>:	push   rbx
   0x00007ffff7dd8d13 <+19>:	mov    rbx,rdx
   0x00007ffff7dd8d16 <+22>:	sub    rsp,0x18
   0x00007ffff7dd8d1a <+26>:	mov    QWORD PTR [rsp],rdi <======= HERE
   0x00007ffff7dd8d1e <+30>:	test   r9,r9
   0x00007ffff7dd8d21 <+33>:	je     0x7ffff7dd8d2f <__libc_start_main+47>
   0x00007ffff7dd8d23 <+35>:	mov    rdi,r9
   0x00007ffff7dd8d26 <+38>:	xor    edx,edx
   0x00007ffff7dd8d28 <+40>:	xor    esi,esi
   0x00007ffff7dd8d2a <+42>:	call   0x7ffff7df14e0 <__cxa_atexit>
   0x00007ffff7dd8d2f <+47>:	mov    rax,QWORD PTR [rip+0x1b20ea]      
```

On aperçoit notre registre rdi qui a sa valeur enregistrée vers le pointeur rsp.
On affiche donc sa valeur à ce moment précis donc :

```
b *__libc_start_main+26
c
x/a $rdi
```

Cela nous donne l'adresse vers main et grâce à ça on peut librement afficher les instructions de main via :

`x/60i 0x0000555555555632`

Après analyse de main j'ai pu voir de nouveau ma chaîne qui apparaissait après avoir saisi le mot de passe et token. Elle semblait être comparée à quelque chose. 

```c
pDG/SbSeHhGM2l16sH
RzFmxRDZH
NCti2PNXH
zY9ZH
```

Tout ce que j'ai fais, j'aurais pu également le faire via de l'analyse statique, mais j'ai voulu commencer avec du dynamique. Après avoir fait cela j'ai préféré partir sur Ghidra pour notamment faire du statique et voir comment le pseudo-code était généré et potentiellement découvrir de nouvelles choses.
J'ai pu constater qu'effectivement on avait une variable local_278 qui était comparée avec une chaîne de caractère qui était elle même générée via une fonction prenant en paramètres le mot de passe que l'utilisateur a saisi, ainsi que sa longueur et le token ainsi que sa longueur.

**Pour plus de détails, la fonction FUN_00101632 (main) sur ghidra se décortique de cette manière : **

- **Entrée des données utilisateur :**
	La fonction demande à l'utilisateur de saisir un nom d'utilisateur, un mot de passe et un token. Ces données sont ensuite lues et stockées dans les variables local_38 (nom d'utilisateur), local_58 (mot de passe) et local_78 (token).

- **Traitement des données :**
	Elle appelle la fonction `FUN_001012a1` avec le mot de passe et le token en tant qu'arguments. Cette fonction prend le mot de passe et le token, puis utilise **RC4** pour chiffrer le mot de passe.
	Il y a également la fonction `FUN_001013d1` qui est appelée avec le mot de passe chiffré. Le résultat est copié dans `local_178`.
	La fonction `FUN_001013d1` prend le mot de passe chiffré et le `password_length` du mot de passe chiffré, puis effectue une opération pour produire une chaîne de caractères.

- **Comparaison de chaînes :**
	La fonction initialise une série de variables (local_278 à local_180) avec des valeurs spécifiques. Ces valeurs, lorsqu'elles sont assemblées, forment la chaîne `pDG/SbSehGM2l16sRzFmxRDZNCti2PNXzY9Z`.

- **Vérification de l'authentification :**
	strcmp est utilisée pour comparer la chaîne résultant du traitement (local_178) avec la chaîne attendue ("pDG/SbSehGM2l16sRzFmxRDZNCti2PNXzY9Z"). Si elles correspondent (iVar1 == 0), le message "Login successful!" est affiché, sinon "Login failed. Incorrect username or password." est affiché.

- **Nettoyage :**
	La mémoire allouée et pointée par local_20 est libérée avec free(local_20). 

A ce moment là je vois que j'aurais besoin de trouver le token pour avoir accès au mot de passe, car il me permettrait de reverse la fonction `FUN_001013d1` qui produit la chaîne de caractère grâce au mot de passe et token, qui est ensuite comparée à `pDG/SbSehGM2l16sRzFmxRDZNCti2PNXzY9Z`.

Du coup, je fais les mêmes manipulations que j'ai fais sur easylogin sur token_validation, je vois que le programme demande en entrée deux parties permettant de générer un token. Je vois également dans Ghidra qu'il y a une condition vérifiant si les user input sont égaux à des constantes. La première partie (le premier user input) passe par une fonction qui semble chiffrer la chaîne. A ce moment là je n'ai aucune idée de l'algorithme de chiffrement utilisé mais je sais que je dois essayer de reverse cet algorithme pour trouver les 2 parties composant mon token.

# Exploitation

J'ai passé beaucoup de temps sur la partie token car je ne connaissais pas du tout l'algorithme, j'ai tenté de bruteforce, mais je me suis vite rendu compte que le nombre de possibilité était trop grand et qu'il me fallait soit faire de l'analyse heuristique pour créer un programme qui pourrait potentiellement plus rapidement trouver le token ou alors trouver un moyen de comprendre l'algorithme mis en place afin de l'inverser pour trouver mon token.
Malheureusement, je n'ai pas eu le temps de finir mon challenge puisqu'à peine avoir découvert l'algorithme et fait un programme, le CTF est venu à termes.

Voici le programme en C qui m'a permis de trouver le token : 

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t arr_1 = 0x1234567;
    uint32_t arr_2 = 0x89ABCDEF;
    uint32_t arr_3 = 0xFEDCBA98;
    uint32_t arr_4 = 0x76543210;
    uint32_t a1 = 0xF27AEDBF;
    uint32_t a2 = 0xED00B66C;
    uint32_t v4 = 3337565984;

    for (int i = 0; i < 32; i++) {
        a2 -= ((a1 >> 5) + arr_4) ^ (a1 + v4) ^ (16 * a1 + arr_3);
        v4 += 1640531527;
        a1 -= (a2 + v4) ^ (16 * a2 + arr_1) ^ ((a2 >> 5) + arr_2);
    }

    printf("%u_%u\n", a1, a2);

    return 0;
}
```

Token : 141414_161616

Et voici à quoi aurait pu ressembler le code pour trouver le flag : 

```python
import base64
import ctypes

arr_1 = ctypes.c_uint(0x1234567)
arr_2 = ctypes.c_uint(0x89ABCDEF)
arr_3 = ctypes.c_uint(0xFEDCBA98)
arr_4 = ctypes.c_uint(0x76543210)
a1 = ctypes.c_uint(0xF27AEDBF)
a2 = ctypes.c_uint(0xED00B66C)
v4 = ctypes.c_uint(3337565984)
for i in range(32):
    a2.value -= ((a1.value >> 5) + arr_4.value) ^ (a1.value + v4.value) ^ (16 * a1.value + arr_3.value)
    v4.value += 1640531527
    a1.value -= (a2.value + v4.value) ^ (16 * a2.value + arr_1.value) ^ ((a2.value >> 5) + arr_2.value)

out = str(a1.value) +"_"+str(a2.value)
data = base64.b64decode("pDG/SbSehGM2l16sRzFmxRDZNCti2PNXzY9Z")
key = out

S = list(range(256))
j = 0
out = []
for i in range(256):
    j = (j + S[i] + ord(key[i % len(key)])) % 256
    S[i], S[j] = S[j], S[i]
i = j = 0
for char in data:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    out.append(chr(char ^ S[(S[i] + S[j]) % 256]))
print("0xL4ugh{",end="")
print("".join(out),end="")
print("}")
```

Flag : `0xL4ugh{more_l0ve_for_xt3a_and_rc4!}`

# Conclusion

Le challenge était très intéressant malgré le fait que je n'ai pas pu le finir. J'aurais peut être également dû changer de challenge quand j'ai vu que je ne reconnaissais pas l'algorithme mis en place pour la génération du token, surtout que j'ai pu voir par la suite que l'autre challenge nommé "nano" pouvait être résolu simplement via un strace en analysant les valeurs du registre r12. Mais c'est bien, j'ai appris des choses et je sais qu'il faut que je gagne en connaissance sur les divers algorithmes de chiffrement qui existent tout en apprenant à reconnaitre leurs patterns lors de phase de rétro-ingénierie. C'est un point qu'il me faut améliorer, et j'en suis conscient grâce à ce CTF.